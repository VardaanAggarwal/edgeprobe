package dev.vardaan.edgeprobe.api.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Everything tunable under {@code edgeprobe.*} in application.yml. Validated at startup. */
@Validated
@ConfigurationProperties("edgeprobe")
public record EdgeprobeProperties(@Valid @NotNull Probe probe, @Valid @NotNull Cache cache,
                                  @Valid @NotNull RateLimit rateLimit) {

    /**
     * @param allowPrivateTargets only for local development: lets the scanner reach localhost and
     *                            private networks. Never enable in a deployed instance (SSRF).
     * @param threads             probe thread pool size; each scan uses up to three threads at once
     */
    public record Probe(@DefaultValue("5s") Duration connectTimeout,
                        @DefaultValue("8s") Duration requestTimeout,
                        @DefaultValue("15s") Duration overallTimeout,
                        @DefaultValue("5") @Min(0) @Max(10) int maxRedirects,
                        @DefaultValue("false") boolean allowPrivateTargets,
                        @DefaultValue("24") @Min(3) int threads) {
    }

    /** @param ttl how long a finished scan is reused for the same URL */
    public record Cache(@DefaultValue("5m") Duration ttl,
                        @DefaultValue("10000") @Min(1) long maxEntries) {
    }

    /** Token bucket per client IP on scan creation: {@code capacity} burst, one token per {@code refillPeriod}. */
    public record RateLimit(@DefaultValue("true") boolean enabled,
                            @DefaultValue("10") @Min(1) int capacity,
                            @DefaultValue("6s") Duration refillPeriod) {
    }
}
