package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.Fixtures.exchange;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Compression, performance and DNS checks. */
class SmallChecksTest {

    private static List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    @Test
    void uncompressedHtmlWarnsButImagesAreSkipped() {
        var compression = new CompressionCheck();
        var html = snapshot().https(exchange("https://example.com/", 200, "content-type", "text/html")).build();
        var png = snapshot().https(exchange("https://example.com/", 200, "content-type", "image/png")).build();
        var gzip = snapshot().https(exchange("https://example.com/", 200,
                "content-type", "application/json", "content-encoding", "gzip")).build();

        assertThat(codes(compression.evaluate(html))).containsExactly("compression.missing");
        assertThat(codes(compression.evaluate(png))).containsExactly("compression.not-applicable");
        assertThat(codes(compression.evaluate(gzip))).containsExactly("compression");
    }

    @ParameterizedTest
    @CsvSource({"300, perf.ttfb", "1200, perf.ttfb.slow", "2500, perf.ttfb.poor"})
    void ttfbThresholds(long millis, String expectedCode) {
        var s = snapshot().https(exchange("https://example.com/", 200, "HTTP/2", millis)).build();
        assertThat(codes(new PerformanceCheck().evaluate(s))).contains(expectedCode);
    }

    @Test
    void http11OnlyWarns() {
        var s = snapshot().https(exchange("https://example.com/", 200, "HTTP/1.1", 100)).build();
        assertThat(codes(new PerformanceCheck().evaluate(s))).contains("perf.http2.missing");
    }

    @Test
    void ipv4OnlySiteWarnsAboutIpv6() {
        var dns = new DnsCheck();
        assertThat(dns.evaluate(snapshot().build())).extracting(Finding::outcome).containsOnly(Outcome.PASS);
        assertThat(codes(dns.evaluate(snapshot().addresses("93.184.215.14").build())))
                .containsExactly("dns.resolved", "dns.ipv6.missing");
    }
}
