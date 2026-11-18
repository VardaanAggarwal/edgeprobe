package dev.vardaan.edgeprobe.cli;

import dev.vardaan.edgeprobe.core.engine.ScanEngine;
import dev.vardaan.edgeprobe.core.model.Outcome;
import dev.vardaan.edgeprobe.core.model.ScanReport;
import dev.vardaan.edgeprobe.core.net.ProberConfig;
import dev.vardaan.edgeprobe.core.net.TargetException;
import java.io.PrintWriter;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Scans sites from a terminal or a CI pipeline, using the same engine as the API but locally,
 * with no server. The exit code makes it usable as a build gate:
 * 0 = within threshold, 1 = threshold breached, 2 = a target could not be scanned.
 */
@Command(name = "edgeprobe", mixinStandardHelpOptions = true, version = "edgeprobe 0.1.0",
        description = "Audit a website's TLS, HTTPS redirect, security headers, caching, compression and performance.",
        exitCodeListHeading = "%nExit codes:%n",
        exitCodeList = {"0:All scans within the --fail-on threshold", "1:At least one scan breached the threshold",
                "2:A URL was invalid, blocked or unresolvable"})
public final class EdgeprobeCli implements Callable<Integer> {

    public enum Threshold { FAIL, WARN, NEVER }

    static final int OK = 0;
    static final int BREACHED = 1;
    static final int UNSCANNABLE = 2;

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1..*", paramLabel = "URL", description = "Sites to scan, e.g. example.com or https://example.com/path")
    List<String> urls;

    @Option(names = "--json", description = "Print reports as JSON.")
    boolean json;

    @Option(names = "--fail-on", defaultValue = "fail",
            description = "Exit 1 when any finding reaches this level: ${COMPLETION-CANDIDATES} (default: ${DEFAULT-VALUE}).")
    Threshold failOn;

    @Option(names = "--timeout", defaultValue = "15s", converter = DurationConverter.class,
            description = "Deadline per scan, e.g. 10s or 1500ms (default: ${DEFAULT-VALUE}).")
    Duration timeout;

    @Option(names = {"-a", "--all"}, description = "Also list passed checks.")
    boolean all;

    public static void main(String[] args) {
        System.exit(commandLine().execute(args));
    }

    /** The configured command; tests use this too, so they exercise exactly what users run. */
    static CommandLine commandLine() {
        return new CommandLine(new EdgeprobeCli()).setCaseInsensitiveEnumValuesAllowed(true);
    }

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();
        ProberConfig config = ProberConfig.defaults()
                .withTimeouts(Duration.ofSeconds(5), timeout, timeout);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        try {
            ScanEngine engine = ScanEngine.create(config, executor, Clock.systemUTC());
            List<ScanReport> reports = new ArrayList<>();
            int exit = OK;
            for (String url : urls) {
                try {
                    ScanReport report = engine.scan(url);
                    reports.add(report);
                    if (!json) {
                        out.print(new ReportPrinter(CommandLine.Help.Ansi.AUTO.enabled(), all).render(report));
                        out.flush();
                    }
                    exit = Math.max(exit, exitCodeFor(report, failOn));
                } catch (TargetException e) {
                    err.println("edgeprobe: " + url + ": " + e.getMessage());
                    exit = UNSCANNABLE;
                }
            }
            if (json && !reports.isEmpty()) {
                JsonMapper mapper = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
                out.println(mapper.writeValueAsString(reports.size() == 1 ? reports.get(0) : reports));
            }
            return exit;
        } finally {
            executor.shutdownNow();
        }
    }

    static int exitCodeFor(ScanReport report, Threshold threshold) {
        return switch (threshold) {
            case NEVER -> OK;
            case FAIL -> report.count(Outcome.FAIL) > 0 ? BREACHED : OK;
            case WARN -> report.count(Outcome.FAIL) + report.count(Outcome.WARN) > 0 ? BREACHED : OK;
        };
    }

    /** Accepts 500ms, 10s, 2m, or ISO-8601 (PT10S). */
    static final class DurationConverter implements CommandLine.ITypeConverter<Duration> {
        @Override
        public Duration convert(String value) {
            String v = value.strip().toLowerCase();
            if (v.startsWith("p")) {
                return Duration.parse(value.strip());
            }
            if (v.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(v.substring(0, v.length() - 2)));
            }
            if (v.endsWith("s")) {
                return Duration.ofSeconds(Long.parseLong(v.substring(0, v.length() - 1)));
            }
            if (v.endsWith("m")) {
                return Duration.ofMinutes(Long.parseLong(v.substring(0, v.length() - 1)));
            }
            return Duration.parse(value);
        }
    }
}
