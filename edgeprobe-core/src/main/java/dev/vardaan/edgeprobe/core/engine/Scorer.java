package dev.vardaan.edgeprobe.core.engine;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.Severity;
import java.util.List;

/**
 * Turns findings into a 0-100 score and a letter grade.
 *
 * <p>Each FAIL subtracts its severity weight and each WARN half of it. Any CRITICAL failure
 * (untrusted or expired certificate, no HTTPS) caps the grade at F regardless of the score,
 * the same rule SSL Labs uses: one broken certificate makes everything else irrelevant.
 */
public final class Scorer {

    private Scorer() {
    }

    public static int score(List<Finding> findings) {
        double penalty = findings.stream().mapToDouble(Finding::penalty).sum();
        return (int) Math.max(0, Math.round(100 - penalty));
    }

    /** "?" means the scan could not see a real page (blocked, error page), so no grade is given. */
    public static final String UNGRADED = "?";

    public static String grade(int score, List<Finding> findings) {
        return grade(score, findings, true);
    }

    /**
     * @param pageUsable whether the final HTTPS response was a real 2xx page. If not, most header
     *                   checks could not run, so a letter grade would be misleading.
     */
    public static String grade(int score, List<Finding> findings, boolean pageUsable) {
        boolean critical = findings.stream()
                .anyMatch(f -> f.outcome() == Outcome.FAIL && f.severity() == Severity.CRITICAL);
        if (critical) {
            return "F";
        }
        if (!pageUsable) {
            return UNGRADED;
        }
        if (score >= 90) {
            return "A";
        }
        if (score >= 80) {
            return "B";
        }
        if (score >= 70) {
            return "C";
        }
        if (score >= 60) {
            return "D";
        }
        return "F";
    }
}
