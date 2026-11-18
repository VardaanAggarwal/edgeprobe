package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.LOW;
import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Whether the page can be cached and revalidated correctly, and whether a CDN or shared cache
 * served it. Includes the classic CDN mistake of caching a response that sets a cookie.
 */
public final class CachingCheck implements Check {

    static final String ID = "caching";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "Cache-Control, validators and 304 revalidation, Vary, cookies on cacheable responses, CDN cache status";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        Optional<List<Finding>> blocked = PageGuard.unusable(s, ID);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        HttpExchange r = s.finalHttps().orElseThrow();
        List<Finding> findings = new ArrayList<>();

        Optional<String> cacheControl = r.joinedHeader("cache-control");
        HeaderDirectives cc = HeaderDirectives.parse(cacheControl.orElse(null), ',');
        // Reusable by a shared cache: not private/no-store/no-cache, and a positive lifetime
        // (s-maxage or max-age > 0), or "public" with no explicit lifetime (heuristic caching).
        boolean explicitLifetime = cc.has("s-maxage") || cc.has("max-age");
        long lifetime = cc.seconds("s-maxage").or(() -> cc.seconds("max-age")).orElse(0L);
        boolean sharedCacheable = !cc.has("private") && !cc.has("no-store") && !cc.has("no-cache")
                && (lifetime > 0 || (cc.has("public") && !explicitLifetime));

        if (cacheControl.isEmpty()) {
            findings.add(Finding.warn(ID, "cache.control.missing", MEDIUM, "No Cache-Control header",
                    "Browsers and CDNs fall back to heuristics, so caching behaviour is unpredictable.",
                    "Set Cache-Control explicitly, for example 'no-cache' for HTML and "
                            + "'public, max-age=31536000, immutable' for fingerprinted assets."));
        } else if (cc.has("no-store")) {
            findings.add(Finding.info(ID, "cache.control.no-store", "Response is not cacheable (no-store)",
                    "Correct for personalised pages; for public pages it forces a full fetch on every visit."));
        } else {
            findings.add(Finding.pass(ID, "cache.control", "Cache-Control set", cacheControl.get()));
        }

        boolean hasValidator = r.hasHeader("etag") || r.hasHeader("last-modified");
        if (!cc.has("no-store")) {
            if (!hasValidator) {
                findings.add(Finding.warn(ID, "cache.validator.missing", LOW, "No ETag or Last-Modified",
                        "Clients cannot revalidate, so an expired copy is always downloaded in full.",
                        "Emit an ETag or Last-Modified so caches can revalidate with a cheap 304."));
            } else {
                findings.add(revalidationFinding(s));
            }
        }

        if (r.joinedHeader("vary").orElse("").strip().equals("*")) {
            findings.add(Finding.warn(ID, "cache.vary.star", MEDIUM, "Vary: * disables shared caching",
                    "No shared cache can reuse this response.",
                    "Vary only on the request headers the response actually depends on."));
        }

        if (sharedCacheable && r.hasHeader("set-cookie")) {
            findings.add(Finding.warn(ID, "cache.cookie-on-public", MEDIUM, "Publicly cacheable response sets a cookie",
                    "A shared cache could store this response and hand one visitor's cookie to others.",
                    "Mark responses that set cookies 'private' or 'no-store', or strip Set-Cookie at the edge."));
        }

        cdnStatus(r).ifPresent(findings::add);
        return findings;
    }

    private Finding revalidationFinding(SiteSnapshot s) {
        Optional<HttpExchange> reval = s.revalidationExchange();
        if (reval.isEmpty()) {
            return Finding.info(ID, "cache.revalidation.untested", "Revalidation not tested",
                    s.error("revalidation").orElse("Validator present, but no conditional request completed."));
        }
        if (reval.get().status() == 304) {
            return Finding.pass(ID, "cache.revalidation", "Conditional request returned 304 Not Modified", "");
        }
        return Finding.warn(ID, "cache.revalidation.ignored", LOW,
                "Server ignores its own validator (" + reval.get().status() + " instead of 304)",
                "A conditional request with the page's validator still returned the full response.",
                "Return 304 when If-None-Match or If-Modified-Since matches; check that the ETag is stable "
                        + "across servers and is not stripped by compression.");
    }

    /** Recognises the standard Cache-Status header plus common CDN-specific ones. */
    private Optional<Finding> cdnStatus(HttpExchange r) {
        List<String> seen = new ArrayList<>();
        for (String name : List.of("cache-status", "x-cache", "cf-cache-status", "x-vercel-cache", "x-served-by")) {
            r.joinedHeader(name).ifPresent(v -> seen.add(name + ": " + v));
        }
        r.joinedHeader("server-timing").filter(v -> v.toLowerCase(Locale.ROOT).contains("cdn-cache"))
                .ifPresent(v -> seen.add("server-timing: " + v));
        r.header("age").ifPresent(v -> seen.add("age: " + v));
        if (seen.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(Finding.info(ID, "cache.cdn", "Served through a shared cache or CDN", String.join("; ", seen)));
    }
}
