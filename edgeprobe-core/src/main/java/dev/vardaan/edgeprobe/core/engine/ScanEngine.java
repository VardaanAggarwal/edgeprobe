package dev.vardaan.edgeprobe.core.engine;

import dev.vardaan.edgeprobe.core.check.Check;
import dev.vardaan.edgeprobe.core.check.Checks;
import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import dev.vardaan.edgeprobe.core.net.HttpSiteProber;
import dev.vardaan.edgeprobe.core.net.Prober;
import dev.vardaan.edgeprobe.core.net.ProberConfig;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import dev.vardaan.edgeprobe.core.net.TargetUrl;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * Runs a scan: probe once, then evaluate every check against the snapshot.
 *
 * <p>Thread-safe; one instance serves concurrent scans. A check that throws produces an ERROR
 * finding instead of failing the scan, so one buggy rule cannot hide the other results.
 */
public final class ScanEngine {

    private final Prober prober;
    private final List<Check> checks;
    private final Clock clock;

    public ScanEngine(Prober prober, List<Check> checks, Clock clock) {
        this.prober = prober;
        this.checks = List.copyOf(checks);
        this.clock = clock;
    }

    /** Engine with the real network prober and all built-in checks. */
    public static ScanEngine create(ProberConfig config, Executor executor, Clock clock) {
        return new ScanEngine(new HttpSiteProber(config, executor), Checks.defaults(clock), clock);
    }

    /** Parses and validates the URL, then scans it. */
    public ScanReport scan(String rawUrl) {
        return scan(TargetUrl.parse(rawUrl));
    }

    public ScanReport scan(TargetUrl target) {
        Instant startedAt = clock.instant();
        long start = System.nanoTime();
        SiteSnapshot snapshot = prober.probe(target);

        List<Finding> findings = new ArrayList<>();
        for (Check check : checks) {
            try {
                findings.addAll(check.evaluate(snapshot));
            } catch (RuntimeException e) {
                findings.add(Finding.error(check.id(), e.getClass().getSimpleName() + ": " + e.getMessage()));
            }
        }

        int score = Scorer.score(findings);
        long durationMs = (System.nanoTime() - start) / 1_000_000;
        return new ScanReport(target.canonical(), target.host(), startedAt, durationMs, score,
                Scorer.grade(score, findings, snapshot.hasUsablePage()), findings);
    }

    public List<Check> checks() {
        return checks;
    }
}
