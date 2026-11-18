package dev.vardaan.edgeprobe.api.scan;

import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.Severity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;

/** API response shapes. Kept separate from JPA entities so the schema can change without breaking clients. */
public final class ScanViews {

    private ScanViews() {
    }

    public record ScanView(UUID id, String url, String host, Instant startedAt, long durationMs, int score,
                           String grade, Summary summary, List<FindingView> findings) {

        static ScanView of(ScanEntity e) {
            List<FindingView> findings = e.getFindings().stream().map(FindingView::of).toList();
            long pass = findings.stream().filter(f -> f.outcome() == Outcome.PASS).count();
            long error = findings.stream().filter(f -> f.outcome() == Outcome.ERROR).count();
            return new ScanView(e.getId(), e.getUrl(), e.getHost(), e.getStartedAt(), e.getDurationMs(),
                    e.getScore(), e.getGrade(), new Summary(pass, e.getWarnCount(), e.getFailCount(), error),
                    findings);
        }
    }

    public record Summary(long pass, long warn, long fail, long error) {
    }

    public record FindingView(String checkId, String code, Outcome outcome, Severity severity, String title,
                              String detail, String remediation) {

        static FindingView of(FindingEntity f) {
            return new FindingView(f.getCheckId(), f.getCode(), f.getOutcome(), f.getSeverity(), f.getTitle(),
                    f.getDetail(), f.getRemediation());
        }
    }

    public record ScanSummaryView(UUID id, String url, String host, Instant startedAt, int score, String grade,
                                  int failCount, int warnCount) {

        static ScanSummaryView of(ScanEntity e) {
            return new ScanSummaryView(e.getId(), e.getUrl(), e.getHost(), e.getStartedAt(), e.getScore(),
                    e.getGrade(), e.getFailCount(), e.getWarnCount());
        }
    }

    /** Stable page envelope; Spring's Page JSON is not a stable contract. */
    public record PageView<T>(List<T> items, int page, int size, long totalItems, int totalPages) {

        static <T> PageView<T> of(Page<T> page) {
            return new PageView<>(page.getContent(), page.getNumber(), page.getSize(), page.getTotalElements(),
                    page.getTotalPages());
        }
    }

    public record CheckView(String id, String description) {
    }
}
