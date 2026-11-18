package dev.vardaan.edgeprobe.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.cli.EdgeprobeCli.Threshold;
import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import dev.vardaan.edgeprobe.core.model.Severity;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class EdgeprobeCliTest {

    private static ScanReport report(Finding... findings) {
        return new ScanReport("https://example.com/", "example.com", Instant.EPOCH, 321, 77, "C", List.of(findings));
    }

    private static final Finding PASS = Finding.pass("tls", "tls.trusted", "Certificate is trusted", "");
    private static final Finding WARN = Finding.warn("caching", "cache.validator.missing", Severity.LOW,
            "No ETag or Last-Modified", "", "Emit an ETag");
    private static final Finding FAIL = Finding.fail("security-headers", "headers.hsts.missing", Severity.HIGH,
            "HSTS header missing", "", "Send Strict-Transport-Security");

    @Test
    void exitCodeFollowsTheThreshold() {
        ScanReport warnOnly = report(PASS, WARN);
        ScanReport failing = report(PASS, WARN, FAIL);

        assertThat(EdgeprobeCli.exitCodeFor(warnOnly, Threshold.FAIL)).isZero();
        assertThat(EdgeprobeCli.exitCodeFor(warnOnly, Threshold.WARN)).isEqualTo(1);
        assertThat(EdgeprobeCli.exitCodeFor(failing, Threshold.FAIL)).isEqualTo(1);
        assertThat(EdgeprobeCli.exitCodeFor(failing, Threshold.NEVER)).isZero();
    }

    @Test
    void printerListsFailuresFirstWithTheirFixAndHidesPassesByDefault() {
        String text = new ReportPrinter(false, false).render(report(PASS, WARN, FAIL));

        assertThat(text).startsWith("https://example.com/  Grade C (77/100)  321 ms");
        assertThat(text.indexOf("HSTS header missing")).isLessThan(text.indexOf("No ETag"));
        assertThat(text).contains("Send Strict-Transport-Security");
        assertThat(text).doesNotContain("Certificate is trusted");
        assertThat(text).contains("1 passed, 1 warnings, 1 failures");
        assertThat(new ReportPrinter(false, true).render(report(PASS))).contains("Certificate is trusted");
    }

    @Test
    void unscannableTargetsExitWith2WithoutTouchingTheNetwork() {
        StringWriter err = new StringWriter();
        CommandLine cli = EdgeprobeCli.commandLine().setErr(new PrintWriter(err));

        int exit = cli.execute("ftp://example.com", "127.0.0.1");

        assertThat(exit).isEqualTo(2);
        assertThat(err.toString())
                .contains("ftp://example.com: Only http and https URLs can be scanned")
                .contains("127.0.0.1: 127.0.0.1 resolves to 127.0.0.1, a loopback address");
    }

    @Test
    void durationsAcceptShortForms() {
        var converter = new EdgeprobeCli.DurationConverter();
        assertThat(converter.convert("1500ms")).isEqualTo(Duration.ofMillis(1500));
        assertThat(converter.convert("10s")).isEqualTo(Duration.ofSeconds(10));
        assertThat(converter.convert("2m")).isEqualTo(Duration.ofMinutes(2));
        assertThat(converter.convert("PT3S")).isEqualTo(Duration.ofSeconds(3));
    }
}
