package dev.vardaan.edgeprobe.cli;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import java.util.Comparator;
import java.util.List;

/** Renders a report for a terminal: failures first, each with its fix. */
final class ReportPrinter {

    private static final String RESET = "\u001B[0m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String GREEN = "\u001B[32m";
    private static final String DIM = "\u001B[2m";
    private static final String BOLD = "\u001B[1m";

    private final boolean color;
    private final boolean showPasses;

    ReportPrinter(boolean color, boolean showPasses) {
        this.color = color;
        this.showPasses = showPasses;
    }

    String render(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        String grade = "?".equals(report.grade())
                ? "Not graded: the site did not return a real page to the scanner"
                : "Grade " + report.grade() + " (" + report.score() + "/100)";
        sb.append(paint(BOLD, report.url()))
                .append("  ")
                .append(paint(gradeColor(report.grade()), grade))
                .append(paint(DIM, "  " + report.durationMs() + " ms"))
                .append('\n');

        List<Finding> shown = report.findings().stream()
                .filter(f -> showPasses || f.outcome() != Outcome.PASS)
                .sorted(Comparator.comparing((Finding f) -> rank(f.outcome()))
                        .thenComparing(f -> -f.severity().weight()))
                .toList();
        for (Finding f : shown) {
            sb.append("  ")
                    .append(paint(outcomeColor(f.outcome()), pad(f.outcome().name(), 5)))
                    .append(' ')
                    .append(pad(f.outcome() == Outcome.PASS ? "" : f.severity().name(), 8))
                    .append(f.title())
                    .append('\n');
            String note = f.outcome() == Outcome.ERROR ? f.detail()
                    : f.outcome() == Outcome.PASS ? "" : f.remediation();
            if (!note.isEmpty()) {
                sb.append("                 ").append(paint(DIM, note)).append('\n');
            }
        }
        sb.append("  ")
                .append(report.count(Outcome.PASS)).append(" passed, ")
                .append(report.count(Outcome.WARN)).append(" warnings, ")
                .append(report.count(Outcome.FAIL)).append(" failures")
                .append(report.count(Outcome.ERROR) > 0 ? ", " + report.count(Outcome.ERROR) + " errors" : "")
                .append("\n\n");
        return sb.toString();
    }

    private static int rank(Outcome outcome) {
        return switch (outcome) {
            case FAIL -> 0;
            case ERROR -> 1;
            case WARN -> 2;
            case PASS -> 3;
        };
    }

    private static String outcomeColor(Outcome outcome) {
        return switch (outcome) {
            case FAIL, ERROR -> RED;
            case WARN -> YELLOW;
            case PASS -> GREEN;
        };
    }

    private static String gradeColor(String grade) {
        return switch (grade) {
            case "A", "B" -> GREEN;
            case "C", "D" -> YELLOW;
            default -> RED;
        };
    }

    private String paint(String code, String text) {
        return color ? code + text + RESET : text;
    }

    private static String pad(String s, int width) {
        return s.length() >= width ? s + " " : s + " ".repeat(width - s.length());
    }
}
