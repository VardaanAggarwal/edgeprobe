package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.LOW;
import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Time to first byte and HTTP version. TTFB thresholds follow web.dev: 800 ms or less is good,
 * over 1800 ms is poor. Measured from the scanner, so it includes connection setup and the
 * network path from wherever edgeprobe runs.
 */
public final class PerformanceCheck implements Check {

    static final String ID = "performance";
    static final long GOOD_TTFB_MS = 800;
    static final long POOR_TTFB_MS = 1800;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "Time to first byte from the scanner, and HTTP/2 support";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        Optional<List<Finding>> blocked = PageGuard.unusable(s, ID);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        HttpExchange r = s.finalHttps().orElseThrow();
        List<Finding> findings = new ArrayList<>();

        long ttfb = r.elapsedMillis();
        if (ttfb > POOR_TTFB_MS) {
            findings.add(Finding.fail(ID, "perf.ttfb.poor", MEDIUM, "Slow time to first byte: " + ttfb + " ms",
                    "Over " + POOR_TTFB_MS + " ms is rated poor.",
                    "Cache the page at the edge, or profile the origin's response time."));
        } else if (ttfb > GOOD_TTFB_MS) {
            findings.add(Finding.warn(ID, "perf.ttfb.slow", LOW, "Time to first byte: " + ttfb + " ms",
                    "Between " + GOOD_TTFB_MS + " and " + POOR_TTFB_MS + " ms needs improvement.",
                    "Cache the page at the edge, or profile the origin's response time."));
        } else {
            findings.add(Finding.pass(ID, "perf.ttfb", "Time to first byte: " + ttfb + " ms", ""));
        }

        if ("HTTP/2".equals(r.httpVersion())) {
            findings.add(Finding.pass(ID, "perf.http2", "HTTP/2 supported", ""));
        } else {
            findings.add(Finding.warn(ID, "perf.http2.missing", LOW, "HTTP/2 not negotiated",
                    "The server answered over " + r.httpVersion() + ", so requests cannot be multiplexed.",
                    "Enable HTTP/2 (and HTTP/3 if available) at the server or CDN."));
        }
        return findings;
    }
}
