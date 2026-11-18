package dev.vardaan.edgeprobe.core.model;

public enum Outcome {
    /** The site meets the check. */
    PASS,
    /** Not broken, but worth fixing. */
    WARN,
    /** The site fails the check. */
    FAIL,
    /** The check itself could not run (for example, the data it needs was not collected). */
    ERROR
}
