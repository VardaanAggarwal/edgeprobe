package dev.vardaan.edgeprobe.core.check;

import java.time.Clock;
import java.util.List;

/** The built-in checks, in report order. */
public final class Checks {

    private Checks() {
    }

    public static List<Check> defaults(Clock clock) {
        return List.of(
                new TlsCheck(clock),
                new HttpsRedirectCheck(),
                new SecurityHeadersCheck(),
                new CachingCheck(),
                new CompressionCheck(),
                new PerformanceCheck(),
                new DnsCheck());
    }
}
