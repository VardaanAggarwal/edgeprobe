package dev.vardaan.edgeprobe.core.net;

/** Collects a {@link SiteSnapshot} for a target. The only part of a scan that touches the network. */
@FunctionalInterface
public interface Prober {

    /**
     * @throws TargetException if the target must not or cannot be scanned at all. Failures of
     *                         individual probes do not throw; they are recorded in the snapshot.
     */
    SiteSnapshot probe(TargetUrl target);
}
