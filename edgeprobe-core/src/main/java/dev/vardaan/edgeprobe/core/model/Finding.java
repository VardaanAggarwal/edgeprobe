package dev.vardaan.edgeprobe.core.model;

import java.util.Objects;

/**
 * One result from one check, for example "HSTS header missing".
 *
 * @param checkId     stable id of the check that produced it, such as {@code tls}
 * @param code        stable machine-readable id of this specific result, such as {@code tls.cert.expiring}
 * @param outcome     pass, warn, fail or error
 * @param severity    how much it matters when it is not a pass
 * @param title       one-line human summary
 * @param detail      what was observed
 * @param remediation how to fix it; empty for passes
 */
public record Finding(String checkId, String code, Outcome outcome, Severity severity,
                      String title, String detail, String remediation) {

    public Finding {
        Objects.requireNonNull(checkId, "checkId");
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(title, "title");
        detail = detail == null ? "" : detail;
        remediation = remediation == null ? "" : remediation;
    }

    public static Finding pass(String checkId, String code, String title, String detail) {
        return new Finding(checkId, code, Outcome.PASS, Severity.INFO, title, detail, "");
    }

    public static Finding info(String checkId, String code, String title, String detail) {
        return new Finding(checkId, code, Outcome.PASS, Severity.INFO, title, detail, "");
    }

    public static Finding warn(String checkId, String code, Severity severity, String title,
                               String detail, String remediation) {
        return new Finding(checkId, code, Outcome.WARN, severity, title, detail, remediation);
    }

    public static Finding fail(String checkId, String code, Severity severity, String title,
                               String detail, String remediation) {
        return new Finding(checkId, code, Outcome.FAIL, severity, title, detail, remediation);
    }

    public static Finding error(String checkId, String detail) {
        return new Finding(checkId, checkId + ".error", Outcome.ERROR, Severity.INFO,
                "Could not verify " + checkId, detail, "");
    }

    /** Points this finding removes from a 100-point score. */
    public double penalty() {
        return switch (outcome) {
            case FAIL -> severity.weight();
            case WARN -> severity.weight() / 2.0;
            case PASS, ERROR -> 0;
        };
    }
}
