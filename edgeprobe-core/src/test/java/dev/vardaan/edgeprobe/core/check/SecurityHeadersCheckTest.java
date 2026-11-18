package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.Fixtures.exchange;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecurityHeadersCheckTest {

    private final SecurityHeadersCheck check = new SecurityHeadersCheck();

    private List<String> codes(String... headers) {
        var s = snapshot().https(exchange("https://example.com/", 200, headers)).build();
        return check.evaluate(s).stream().map(Finding::code).toList();
    }

    @Test
    void wellConfiguredPagePasses() {
        assertThat(check.evaluate(snapshot().build())).extracting(Finding::outcome).containsOnly(Outcome.PASS);
    }

    @Test
    void bareResponseFlagsEveryMissingHeader() {
        assertThat(codes()).containsExactly(
                "headers.hsts.missing", "headers.csp.missing", "headers.framing.missing",
                "headers.nosniff.missing", "headers.referrer-policy.missing");
    }

    @Test
    void shortHstsWarns() {
        assertThat(codes("strict-transport-security", "max-age=300")).contains("headers.hsts.short");
    }

    @Test
    void hstsDirectivesAreCaseInsensitive() {
        var s = snapshot().https(exchange("https://example.com/", 200,
                "Strict-Transport-Security", "MAX-AGE=63072000; IncludeSubDomains; preload")).build();
        Finding hsts = check.evaluate(s).get(0);
        assertThat(hsts.code()).isEqualTo("headers.hsts");
        assertThat(hsts.detail()).contains("includeSubDomains", "preload");
    }

    @Test
    void unsafeInlineCspWarnsUnlessNoncesAreUsed() {
        assertThat(codes("content-security-policy", "script-src 'self' 'unsafe-inline'"))
                .contains("headers.csp.unsafe-inline");
        assertThat(codes("content-security-policy", "script-src 'self' 'unsafe-inline' 'nonce-abc'"))
                .contains("headers.csp");
    }

    @Test
    void xFrameOptionsAloneProtectsAgainstFraming() {
        assertThat(codes("x-frame-options", "sameorigin")).contains("headers.framing");
    }

    @Test
    void versionedServerHeaderIsReported() {
        assertThat(codes("server", "nginx/1.18.0")).contains("headers.version-disclosure");
        assertThat(codes("server", "nginx")).doesNotContain("headers.version-disclosure");
    }

    @Test
    void noFinalResponseIsAnError() {
        var s = snapshot().https().error("https", "connection refused").build();
        assertThat(check.evaluate(s)).singleElement()
                .satisfies(f -> assertThat(f.outcome()).isEqualTo(Outcome.ERROR));
    }
}
