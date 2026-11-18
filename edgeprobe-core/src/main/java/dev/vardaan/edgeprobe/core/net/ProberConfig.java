package dev.vardaan.edgeprobe.core.net;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.SSLContext;

/**
 * Prober settings. Use {@link #defaults()} and the {@code with*} methods.
 *
 * @param connectTimeout TCP connect timeout per request
 * @param requestTimeout time allowed for response headers per request
 * @param overallTimeout deadline for the whole probe; unfinished probes are recorded as timed out
 * @param maxRedirects   redirects followed per chain before it is treated as a loop
 * @param httpPort       port for plain-HTTP probes (80 in production; tests use an ephemeral port)
 * @param httpsPort      port for HTTPS and TLS probes
 * @param sslContext     trust configuration for HTTPS requests and the TLS probe
 * @param policy         which resolved addresses may be contacted
 * @param dns            name resolution
 * @param userAgent      User-Agent sent with every request
 */
public record ProberConfig(Duration connectTimeout, Duration requestTimeout, Duration overallTimeout,
                           int maxRedirects, int httpPort, int httpsPort, SSLContext sslContext,
                           AddressPolicy policy, DnsResolver dns, String userAgent) {

    public ProberConfig {
        Objects.requireNonNull(connectTimeout);
        Objects.requireNonNull(requestTimeout);
        Objects.requireNonNull(overallTimeout);
        Objects.requireNonNull(sslContext);
        Objects.requireNonNull(policy);
        Objects.requireNonNull(dns);
        if (maxRedirects < 0) {
            throw new IllegalArgumentException("maxRedirects must be >= 0");
        }
    }

    public static ProberConfig defaults() {
        try {
            return new ProberConfig(Duration.ofSeconds(5), Duration.ofSeconds(8), Duration.ofSeconds(15),
                    5, 80, 443, SSLContext.getDefault(), AddressPolicy.publicOnly(), DnsResolver.SYSTEM,
                    "edgeprobe/0.1 (+https://github.com/VardaanAggarwal/edgeprobe)");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No default SSLContext", e);
        }
    }

    public ProberConfig withTimeouts(Duration connect, Duration request, Duration overall) {
        return new ProberConfig(connect, request, overall, maxRedirects, httpPort, httpsPort,
                sslContext, policy, dns, userAgent);
    }

    public ProberConfig withMaxRedirects(int max) {
        return new ProberConfig(connectTimeout, requestTimeout, overallTimeout, max, httpPort, httpsPort,
                sslContext, policy, dns, userAgent);
    }

    public ProberConfig withPorts(int http, int https) {
        return new ProberConfig(connectTimeout, requestTimeout, overallTimeout, maxRedirects, http, https,
                sslContext, policy, dns, userAgent);
    }

    public ProberConfig withSslContext(SSLContext context) {
        return new ProberConfig(connectTimeout, requestTimeout, overallTimeout, maxRedirects, httpPort,
                httpsPort, context, policy, dns, userAgent);
    }

    public ProberConfig withPolicy(AddressPolicy addressPolicy) {
        return new ProberConfig(connectTimeout, requestTimeout, overallTimeout, maxRedirects, httpPort,
                httpsPort, sslContext, addressPolicy, dns, userAgent);
    }

    public ProberConfig withDns(DnsResolver resolver) {
        return new ProberConfig(connectTimeout, requestTimeout, overallTimeout, maxRedirects, httpPort,
                httpsPort, sslContext, policy, resolver, userAgent);
    }
}
