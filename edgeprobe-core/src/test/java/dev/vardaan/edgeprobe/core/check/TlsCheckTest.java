package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.Fixtures.NOW;
import static dev.vardaan.edgeprobe.core.Fixtures.cert;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.Severity;
import dev.vardaan.edgeprobe.core.net.TlsInfo;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TlsCheckTest {

    private static final long DAY = 86_400;
    private final TlsCheck check = new TlsCheck(Clock.fixed(NOW, ZoneOffset.UTC));

    private static TlsInfo tlsExpiringIn(long days) {
        return new TlsInfo(true, null, "TLSv1.3", "TLS_AES_128_GCM_SHA256",
                List.of(cert(NOW.minusSeconds(60 * DAY), NOW.plusSeconds(days * DAY + 3600))));
    }

    private static Finding byCodePrefix(List<Finding> findings, String prefix) {
        return findings.stream().filter(f -> f.code().startsWith(prefix)).findFirst().orElseThrow();
    }

    @Test
    void healthyCertificatePassesEverything() {
        List<Finding> findings = check.evaluate(snapshot().build());
        assertThat(findings).extracting(Finding::outcome).containsOnly(Outcome.PASS);
    }

    @ParameterizedTest
    @CsvSource({"90, PASS, INFO", "15, WARN, MEDIUM", "3, FAIL, HIGH"})
    void expiryThresholds(long days, Outcome outcome, Severity severity) {
        Finding expiry = byCodePrefix(check.evaluate(snapshot().tls(tlsExpiringIn(days)).build()), "tls.cert");
        assertThat(expiry.outcome()).isEqualTo(outcome);
        assertThat(expiry.severity()).isEqualTo(severity);
    }

    @Test
    void expiredCertificateIsCritical() {
        TlsInfo expired = new TlsInfo(true, null, "TLSv1.3", "x",
                List.of(cert(NOW.minusSeconds(100 * DAY), NOW.minusSeconds(DAY))));
        Finding f = byCodePrefix(check.evaluate(snapshot().tls(expired).build()), "tls.cert");
        assertThat(f.code()).isEqualTo("tls.cert.expired");
        assertThat(f.severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void untrustedCertificateExplainsWhy() {
        TlsInfo untrusted = new TlsInfo(false, "certificate does not cover this host name", "TLSv1.3", "x",
                List.of(cert(NOW.minusSeconds(DAY), NOW.plusSeconds(80 * DAY))));
        Finding f = byCodePrefix(check.evaluate(snapshot().tls(untrusted).build()), "tls.untrusted");
        assertThat(f.outcome()).isEqualTo(Outcome.FAIL);
        assertThat(f.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(f.detail()).startsWith("Certificate does not cover this host name");
    }

    @Test
    void missingHandshakeMeansNoHttps() {
        List<Finding> findings = check.evaluate(snapshot().tls(null).error("tls", "connection refused").build());
        assertThat(findings).singleElement().satisfies(f -> {
            assertThat(f.code()).isEqualTo("tls.unavailable");
            assertThat(f.detail()).contains("connection refused");
        });
    }

    @Test
    void legacyProtocolWeakKeyAndSha1AllFail() {
        TlsInfo weak = new TlsInfo(true, null, "TLSv1.1", "x", List.of(new TlsInfo.CertInfo(
                "CN=old", "CN=old-ca", NOW.minusSeconds(DAY), NOW.plusSeconds(200 * DAY), List.of(),
                "SHA1withRSA", "RSA", 1024)));
        List<Finding> findings = check.evaluate(snapshot().tls(weak).build());
        assertThat(findings).extracting(Finding::code)
                .contains("tls.protocol.legacy", "tls.key.weak", "tls.signature.weak");
    }
}
