package dev.vardaan.edgeprobe.core.model;

/**
 * How much a failed check matters. The weight is the number of points a FAIL removes from the
 * 100-point score; a WARN removes half of it.
 */
public enum Severity {
    INFO(0),
    LOW(3),
    MEDIUM(8),
    HIGH(15),
    CRITICAL(40);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }
}
