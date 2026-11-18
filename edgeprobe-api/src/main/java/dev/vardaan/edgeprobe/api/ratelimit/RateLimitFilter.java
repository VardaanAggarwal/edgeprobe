package dev.vardaan.edgeprobe.api.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.vardaan.edgeprobe.api.config.EdgeprobeProperties;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rate-limits scan creation per client IP. Every scan makes outbound connections to a third-party
 * site, so an unlimited endpoint would turn this service into a tool for hammering other sites.
 *
 * <p>Buckets live in a Caffeine cache that drops idle clients after ten minutes and caps the
 * number of tracked IPs, so a flood of distinct addresses cannot exhaust memory.
 *
 * <p>Behind a proxy, set {@code server.forward-headers-strategy=native} so the remote address is
 * the real client. Limits are per instance; a multi-instance deployment needs a shared store.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final EdgeprobeProperties.RateLimit config;
    private final MeterRegistry meters;
    private final Cache<String, TokenBucket> buckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(10))
            .maximumSize(100_000)
            .build();

    public RateLimitFilter(EdgeprobeProperties properties, MeterRegistry meters) {
        this.config = properties.rateLimit();
        this.meters = meters;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !config.enabled()
                || !"POST".equals(request.getMethod())
                || !request.getRequestURI().equals("/api/v1/scans");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        TokenBucket bucket = buckets.get(request.getRemoteAddr(),
                ip -> new TokenBucket(config.capacity(), config.refillPeriod(), System::nanoTime));
        long waitNanos = bucket.tryConsume();
        if (waitNanos == 0) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(bucket.available()));
            chain.doFilter(request, response);
            return;
        }
        meters.counter("edgeprobe.ratelimit.rejected").increment();
        long retryAfter = Math.max(1, TimeUnit.NANOSECONDS.toSeconds(waitNanos) + 1);
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        response.setContentType("application/problem+json");
        response.getWriter().write("{\"type\":\"about:blank\",\"title\":\"Too Many Requests\",\"status\":429,"
                + "\"detail\":\"Scan rate limit reached. Retry after " + retryAfter + " seconds.\"}");
    }
}
