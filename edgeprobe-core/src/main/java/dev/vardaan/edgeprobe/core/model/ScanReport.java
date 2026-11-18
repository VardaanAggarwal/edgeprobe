package dev.vardaan.edgeprobe.core.model;

import java.time.Instant;
import java.util.List;

/**
 * The full result of scanning one URL.
 *
 * @param url        the normalized URL that was scanned
 * @param host       its host name
 * @param startedAt  when the scan began
 * @param durationMs wall-clock time for probing plus checks
 * @param score      0 to 100
 * @param grade      A to F, derived from the score
 * @param findings   every finding, in check order
 */
public record ScanReport(String url, String host, Instant startedAt, long durationMs,
                         int score, String grade, List<Finding> findings) {

    public ScanReport {
        findings = List.copyOf(findings);
    }

    public long count(Outcome outcome) {
        return findings.stream().filter(f -> f.outcome() == outcome).count();
    }
}
