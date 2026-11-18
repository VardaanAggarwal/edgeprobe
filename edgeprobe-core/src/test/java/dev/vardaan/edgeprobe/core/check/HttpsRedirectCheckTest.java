package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.Fixtures.exchange;
import static dev.vardaan.edgeprobe.core.Fixtures.goodPage;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import java.util.List;
import org.junit.jupiter.api.Test;

class HttpsRedirectCheckTest {

    private final HttpsRedirectCheck check = new HttpsRedirectCheck();

    private List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    @Test
    void permanentSameHostRedirectPasses() {
        List<Finding> findings = check.evaluate(snapshot().build());
        assertThat(findings).extracting(Finding::outcome).containsOnly(Outcome.PASS);
    }

    @Test
    void plainHttpContentFails() {
        var s = snapshot().http(exchange("http://example.com/", 200, "content-type", "text/html")).build();
        assertThat(codes(check.evaluate(s))).containsExactly("redirect.missing");
    }

    @Test
    void blockedPlainHttpIsUnverifiedNotAFailure() {
        var s = snapshot().http(exchange("http://example.com/", 403)).build();
        assertThat(check.evaluate(s)).singleElement()
                .satisfies(f -> assertThat(f.outcome()).isEqualTo(Outcome.ERROR));
    }

    @Test
    void temporaryRedirectWarns() {
        var s = snapshot().http(exchange("http://example.com/", 302, "location", "https://example.com/"), goodPage())
                .build();
        assertThat(codes(check.evaluate(s))).containsExactly("redirect.temporary");
    }

    @Test
    void redirectThatStaysOnHttpFails() {
        var s = snapshot().http(
                exchange("http://example.com/", 301, "location", "http://www.example.com/"),
                exchange("http://www.example.com/", 200)).build();
        assertThat(codes(check.evaluate(s))).containsExactly("redirect.not-https");
    }

    @Test
    void crossHostFirstRedirectWarns() {
        var s = snapshot().http(
                exchange("http://example.com/", 301, "location", "https://www.example.com/"),
                exchange("https://www.example.com/", 200)).build();
        assertThat(codes(check.evaluate(s))).containsExactly("redirect.permanent", "redirect.cross-host");
    }

    @Test
    void relativeLocationIsResolvedAgainstRequestUrl() {
        var s = snapshot().http(exchange("http://example.com/a", 301, "location", "https://example.com/b"),
                goodPage()).build();
        assertThat(codes(check.evaluate(s))).containsExactly("redirect.permanent");
    }

    @Test
    void unreachablePort80Warns() {
        var s = snapshot().http().error("http", "connection refused").build();
        Finding f = check.evaluate(s).get(0);
        assertThat(f.code()).isEqualTo("redirect.http-unreachable");
        assertThat(f.detail()).contains("connection refused");
    }

    @Test
    void loopsAndLongChainsAreFlagged() {
        var hop = exchange("https://example.com/", 301, "location", "https://example.com/x");
        var s = snapshot().https(hop, hop, hop, hop).loop(true).error("https", "stopped after 5 redirects").build();
        assertThat(codes(check.evaluate(s))).contains("redirect.loop", "redirect.chain-long");
    }
}
