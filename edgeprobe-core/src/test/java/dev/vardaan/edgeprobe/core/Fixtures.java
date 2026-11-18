package dev.vardaan.edgeprobe.core;

import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import dev.vardaan.edgeprobe.core.net.TargetUrl;
import dev.vardaan.edgeprobe.core.net.TlsInfo;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Hand-built snapshots, so checks can be tested without a network. */
public final class Fixtures {

    public static final Instant NOW = Instant.parse("2026-11-18T00:00:00Z");

    private Fixtures() {
    }

    /** headers given as alternating name, value pairs. */
    public static HttpExchange exchange(String uri, int status, String... headers) {
        return exchange(uri, status, "HTTP/2", 120, headers);
    }

    public static HttpExchange exchange(String uri, int status, String version, long millis, String... headers) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            map.computeIfAbsent(headers[i], k -> new ArrayList<>()).add(headers[i + 1]);
        }
        return new HttpExchange(URI.create(uri), status, version, map, millis);
    }

    public static TlsInfo.CertInfo cert(Instant notBefore, Instant notAfter) {
        return new TlsInfo.CertInfo("CN=example.com", "CN=R11,O=Let's Encrypt,C=US", notBefore, notAfter,
                List.of("example.com"), "SHA256withRSA", "RSA", 2048);
    }

    public static TlsInfo goodTls() {
        return new TlsInfo(true, null, "TLSv1.3", "TLS_AES_128_GCM_SHA256",
                List.of(cert(NOW.minusSeconds(86_400 * 10), NOW.plusSeconds(86_400 * 80))));
    }

    /** A well-configured site; tests change one thing at a time. */
    public static HttpExchange goodPage() {
        return exchange("https://example.com/", 200,
                "content-type", "text/html; charset=utf-8",
                "content-encoding", "br",
                "cache-control", "no-cache",
                "etag", "\"abc\"",
                "strict-transport-security", "max-age=31536000; includeSubDomains",
                "content-security-policy", "default-src 'self'; frame-ancestors 'self'",
                "x-content-type-options", "nosniff",
                "referrer-policy", "strict-origin-when-cross-origin");
    }

    public static Builder snapshot() {
        return new Builder();
    }

    public static final class Builder {
        private List<String> addresses = List.of("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c");
        private List<HttpExchange> httpsChain = List.of(goodPage());
        private List<HttpExchange> httpChain = List.of(
                exchange("http://example.com/", 301, "location", "https://example.com/"),
                goodPage());
        private boolean loop;
        private TlsInfo tls = goodTls();
        private HttpExchange revalidation = exchange("https://example.com/", 304);
        private final Map<String, String> errors = new HashMap<>();

        public Builder addresses(String... a) {
            addresses = List.of(a);
            return this;
        }

        public Builder https(HttpExchange... hops) {
            httpsChain = List.of(hops);
            return this;
        }

        public Builder http(HttpExchange... hops) {
            httpChain = List.of(hops);
            return this;
        }

        public Builder loop(boolean value) {
            loop = value;
            return this;
        }

        public Builder tls(TlsInfo value) {
            tls = value;
            return this;
        }

        public Builder revalidation(HttpExchange value) {
            revalidation = value;
            return this;
        }

        public Builder error(String probe, String message) {
            errors.put(probe, message);
            return this;
        }

        public SiteSnapshot build() {
            return new SiteSnapshot(TargetUrl.parse("https://example.com/"), addresses, 12,
                    httpsChain, httpChain, loop, tls, revalidation, errors);
        }
    }
}
