package dev.vardaan.edgeprobe.core.engine;

import static dev.vardaan.edgeprobe.core.Fixtures.NOW;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.check.Check;
import dev.vardaan.edgeprobe.core.check.Checks;
import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import dev.vardaan.edgeprobe.core.model.Severity;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ScanEngineTest {

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void wellConfiguredSiteScoresAnA() {
        ScanEngine engine = new ScanEngine(target -> snapshot().build(), Checks.defaults(clock), clock);

        ScanReport report = engine.scan("example.com");

        assertThat(report.url()).isEqualTo("https://example.com/");
        assertThat(report.grade()).isEqualTo("A");
        assertThat(report.score()).isEqualTo(100);
        assertThat(report.count(Outcome.FAIL)).isZero();
    }

    @Test
    void aThrowingCheckBecomesAnErrorFindingAndOtherChecksStillRun() {
        Check broken = new Check() {
            public String id() {
                return "broken";
            }

            public String description() {
                return "always throws";
            }

            public List<Finding> evaluate(SiteSnapshot s) {
                throw new IllegalStateException("boom");
            }
        };
        List<Check> checks = new ArrayList<>(Checks.defaults(clock));
        checks.add(0, broken);
        ScanEngine engine = new ScanEngine(target -> snapshot().build(), checks, clock);

        ScanReport report = engine.scan("example.com");

        assertThat(report.findings().get(0)).satisfies(f -> {
            assertThat(f.outcome()).isEqualTo(Outcome.ERROR);
            assertThat(f.detail()).contains("boom");
        });
        assertThat(report.findings()).hasSizeGreaterThan(10);
    }

    @Test
    void botProtection403IsUngradedInsteadOfFalseFailures() {
        // Regression from a live scan: a CDN's bot protection answered 403 on both http:// and
        // https://, and the headers of the block page were reported as the site's failures.
        var blockPage = dev.vardaan.edgeprobe.core.Fixtures.exchange("https://example.com/", 403,
                "content-type", "text/html", "cache-control", "max-age=0", "set-cookie", "bm=1");
        var httpBlock = dev.vardaan.edgeprobe.core.Fixtures.exchange("http://example.com/", 403);
        ScanEngine engine = new ScanEngine(target -> snapshot().https(blockPage).http(httpBlock).build(),
                Checks.defaults(clock), clock);

        ScanReport report = engine.scan("example.com");

        assertThat(report.grade()).isEqualTo(Scorer.UNGRADED);
        assertThat(report.count(Outcome.FAIL)).isZero();
        assertThat(report.findings()).filteredOn(f -> f.outcome() == Outcome.ERROR)
                .extracting(Finding::checkId)
                .contains("https-redirect", "security-headers", "caching", "compression", "performance");
    }

    @Test
    void criticalFailureCapsGradeAtFEvenWithAHighScore() {
        List<Finding> findings = List.of(
                Finding.fail("tls", "tls.cert.expired", Severity.CRITICAL, "expired", "", ""));
        int score = Scorer.score(findings);
        assertThat(score).isEqualTo(60);
        assertThat(Scorer.grade(score, findings)).isEqualTo("F");
    }

    @Test
    void warningsCostHalfOfAFailure() {
        List<Finding> findings = List.of(
                Finding.warn("x", "a", Severity.MEDIUM, "t", "", ""),
                Finding.fail("x", "b", Severity.HIGH, "t", "", ""));
        assertThat(Scorer.score(findings)).isEqualTo(81);
        assertThat(Scorer.grade(81, findings)).isEqualTo("B");
    }
}
