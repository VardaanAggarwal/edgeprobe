package dev.vardaan.edgeprobe.core.check;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.List;

/**
 * One family of rules evaluated against a {@link SiteSnapshot}.
 *
 * <p>Implementations must be pure: no I/O, no shared mutable state. All network access happens
 * in the prober, so a check is a function from observed data to findings and can be tested with
 * a hand-built snapshot.
 */
public interface Check {

    /** Stable id used in reports and APIs, such as {@code tls}. */
    String id();

    /** One-line description for documentation and the API's check listing. */
    String description();

    List<Finding> evaluate(SiteSnapshot snapshot);
}
