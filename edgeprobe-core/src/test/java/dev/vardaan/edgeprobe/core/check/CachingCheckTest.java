package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.Fixtures.exchange;
import static dev.vardaan.edgeprobe.core.Fixtures.snapshot;
import static org.assertj.core.api.Assertions.assertThat;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import java.util.List;
import org.junit.jupiter.api.Test;

class CachingCheckTest {

    private final CachingCheck check = new CachingCheck();

    private List<Finding> evaluate(String... headers) {
        return check.evaluate(snapshot().https(exchange("https://example.com/", 200, headers)).build());
    }

    private static List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    @Test
    void cacheControlWithWorkingRevalidationPasses() {
        assertThat(check.evaluate(snapshot().build())).extracting(Finding::outcome).containsOnly(Outcome.PASS);
    }

    @Test
    void missingCacheControlAndValidatorWarn() {
        assertThat(codes(evaluate())).containsExactly("cache.control.missing", "cache.validator.missing");
    }

    @Test
    void serverThatIgnoresItsOwnEtagWarns() {
        var s = snapshot()
                .https(exchange("https://example.com/", 200, "cache-control", "no-cache", "etag", "\"v1\""))
                .revalidation(exchange("https://example.com/", 200))
                .build();
        assertThat(codes(check.evaluate(s))).contains("cache.revalidation.ignored");
    }

    @Test
    void publicResponseSettingCookieWarns() {
        assertThat(codes(evaluate("cache-control", "public, max-age=600", "set-cookie", "session=abc", "etag", "\"x\"")))
                .contains("cache.cookie-on-public");
        assertThat(codes(evaluate("cache-control", "private, max-age=600", "set-cookie", "session=abc")))
                .doesNotContain("cache.cookie-on-public");
        // max-age=0 means a shared cache cannot reuse the response, so the cookie is not at risk.
        assertThat(codes(evaluate("cache-control", "max-age=0", "set-cookie", "session=abc")))
                .doesNotContain("cache.cookie-on-public");
        assertThat(codes(evaluate("cache-control", "public", "set-cookie", "session=abc")))
                .contains("cache.cookie-on-public");
    }

    @Test
    void noStoreSkipsValidatorAdvice() {
        assertThat(codes(evaluate("cache-control", "no-store"))).containsExactly("cache.control.no-store");
    }

    @Test
    void varyStarWarns() {
        assertThat(codes(evaluate("cache-control", "no-cache", "etag", "\"x\"", "vary", "*")))
                .contains("cache.vary.star");
    }

    @Test
    void detectsCdnCacheStatusIncludingServerTiming() {
        Finding cdn = evaluate("cache-control", "no-store", "server-timing", "cdn-cache; desc=HIT", "age", "42")
                .stream().filter(f -> f.code().equals("cache.cdn")).findFirst().orElseThrow();
        assertThat(cdn.detail()).contains("cdn-cache; desc=HIT").contains("age: 42");
    }
}
