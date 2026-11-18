package dev.vardaan.edgeprobe.api.scan;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.vardaan.edgeprobe.api.config.EdgeprobeProperties;
import dev.vardaan.edgeprobe.api.scan.ScanViews.ScanSummaryView;
import dev.vardaan.edgeprobe.api.scan.ScanViews.ScanView;
import dev.vardaan.edgeprobe.core.engine.ScanEngine;
import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import dev.vardaan.edgeprobe.core.net.TargetUrl;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Runs scans with two layers in front of the engine:
 *
 * <ol>
 *   <li><b>Result cache.</b> A finished scan is reused for the same URL for {@code edgeprobe.cache.ttl}.
 *       Caffeine bounds it by size and expires entries on write, so memory stays flat.</li>
 *   <li><b>Request coalescing.</b> If a scan for a URL is already running, later callers wait for
 *       that scan instead of starting their own. A burst of identical requests therefore makes one
 *       set of outbound connections, the same idea as request collapsing in a CDN.</li>
 * </ol>
 *
 * <p>The network work happens outside any database transaction; only the insert is transactional,
 * so a slow site never holds a pooled connection.
 */
@Service
public class ScanService {

    public enum CacheStatus { MISS, HIT, COALESCED }

    public record ScanResult(ScanView scan, CacheStatus cacheStatus) {
    }

    private final ScanEngine engine;
    private final ScanRepository repository;
    private final TransactionTemplate transactions;
    private final MeterRegistry meters;
    private final Timer scanTimer;
    private final Cache<String, ScanView> recent;
    private final ConcurrentMap<String, CompletableFuture<ScanView>> inFlight = new ConcurrentHashMap<>();

    public ScanService(ScanEngine engine, ScanRepository repository, TransactionTemplate transactions,
                       EdgeprobeProperties properties, MeterRegistry meters) {
        this.engine = engine;
        this.repository = repository;
        this.transactions = transactions;
        this.meters = meters;
        this.scanTimer = Timer.builder("edgeprobe.scan.duration")
                .description("Time to probe a site and evaluate all checks")
                .publishPercentileHistogram()
                .register(meters);
        this.recent = Caffeine.newBuilder()
                .expireAfterWrite(properties.cache().ttl())
                .maximumSize(properties.cache().maxEntries())
                .build();
    }

    /**
     * @param fresh skip the result cache. Still coalesces with a scan already in flight.
     */
    public ScanResult scan(String rawUrl, boolean fresh) {
        TargetUrl target = TargetUrl.parse(rawUrl);
        String key = target.canonical();

        if (!fresh) {
            ScanView cached = recent.getIfPresent(key);
            if (cached != null) {
                return count(new ScanResult(cached, CacheStatus.HIT));
            }
        }

        CompletableFuture<ScanView> mine = new CompletableFuture<>();
        CompletableFuture<ScanView> running = inFlight.putIfAbsent(key, mine);
        if (running != null) {
            return count(new ScanResult(await(running), CacheStatus.COALESCED));
        }

        try {
            ScanReport report = scanTimer.record(() -> engine.scan(target));
            ScanView view = transactions.execute(status -> ScanView.of(repository.save(toEntity(report))));
            recent.put(key, view);
            mine.complete(view);
            return count(new ScanResult(view, CacheStatus.MISS));
        } catch (RuntimeException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, mine);
        }
    }

    public ScanView get(UUID id) {
        return transactions.execute(status -> repository.findWithFindingsById(id)
                .map(ScanView::of)
                .orElseThrow(() -> new ScanNotFoundException(id)));
    }

    public ScanViews.PageView<ScanSummaryView> history(String host, int page, int size) {
        PageRequest request = PageRequest.of(page, size);
        var result = host == null || host.isBlank()
                ? repository.findAllByOrderByStartedAtDesc(request)
                : repository.findByHostOrderByStartedAtDesc(TargetUrl.parse(host).host(), request);
        return ScanViews.PageView.of(result.map(ScanSummaryView::of));
    }

    private ScanResult count(ScanResult result) {
        meters.counter("edgeprobe.scan.requests", "cache", result.cacheStatus().name().toLowerCase()).increment();
        return result;
    }

    /** Waits for another caller's scan; rethrows its failure (bad target, blocked target) as-is. */
    private static ScanView await(CompletableFuture<ScanView> running) {
        try {
            return running.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException cause) {
                throw cause;
            }
            throw e;
        }
    }

    private static ScanEntity toEntity(ScanReport report) {
        ScanEntity scan = new ScanEntity(UUID.randomUUID(), report.url(), report.host(), report.startedAt(),
                report.durationMs(), report.score(), report.grade(),
                (int) report.count(Outcome.FAIL), (int) report.count(Outcome.WARN));
        for (Finding f : report.findings()) {
            scan.addFinding(new FindingEntity(f.checkId(), f.code(), f.outcome(), f.severity(), f.title(),
                    f.detail(), f.remediation()));
        }
        return scan;
    }
}
