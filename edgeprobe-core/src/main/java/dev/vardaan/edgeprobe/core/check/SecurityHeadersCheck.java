package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.HIGH;
import static dev.vardaan.edgeprobe.core.model.Severity.LOW;
import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/** HSTS, CSP, clickjacking protection, MIME sniffing, referrer policy and version disclosure. */
public final class SecurityHeadersCheck implements Check {

    static final String ID = "security-headers";
    /** Six months: the minimum max-age most guidance accepts (preload requires one year). */
    static final long MIN_HSTS_SECONDS = 15_768_000L;
    private static final Pattern VERSION = Pattern.compile("\\d+\\.\\d+");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "HSTS, Content-Security-Policy, framing protection, nosniff, Referrer-Policy, version disclosure";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        Optional<List<Finding>> blocked = PageGuard.unusable(s, ID);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        HttpExchange r = s.finalHttps().orElseThrow();
        List<Finding> findings = new ArrayList<>();
        findings.add(hsts(r));
        findings.add(csp(r));
        findings.add(framing(r));
        findings.add(nosniff(r));
        findings.add(referrerPolicy(r));
        versionDisclosure(r).ifPresent(findings::add);
        return findings;
    }

    private Finding hsts(HttpExchange r) {
        Optional<String> header = r.header("strict-transport-security");
        if (header.isEmpty()) {
            return Finding.fail(ID, "headers.hsts.missing", HIGH, "HSTS header missing",
                    "Without Strict-Transport-Security, a first visit over http:// can be intercepted.",
                    "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.");
        }
        HeaderDirectives d = HeaderDirectives.parse(header.get(), ';');
        long maxAge = d.seconds("max-age").orElse(0L);
        if (maxAge < MIN_HSTS_SECONDS) {
            return Finding.warn(ID, "headers.hsts.short", MEDIUM, "HSTS max-age is short (" + maxAge + "s)",
                    header.get(), "Use max-age of at least 15768000 (6 months); 31536000 is typical.");
        }
        String extras = (d.has("includesubdomains") ? "includeSubDomains" : "no includeSubDomains")
                + (d.has("preload") ? ", preload" : "");
        return Finding.pass(ID, "headers.hsts", "HSTS enabled", "max-age=" + maxAge + ", " + extras);
    }

    private Finding csp(HttpExchange r) {
        if (r.hasHeader("content-security-policy")) {
            String policy = r.joinedHeader("content-security-policy").orElse("");
            if (policy.contains("'unsafe-inline'") && !policy.contains("'nonce-") && !policy.contains("'sha")) {
                return Finding.warn(ID, "headers.csp.unsafe-inline", LOW, "CSP allows 'unsafe-inline'",
                        "Inline scripts are allowed, which removes most of CSP's XSS protection.",
                        "Replace 'unsafe-inline' with nonces or hashes.");
            }
            return Finding.pass(ID, "headers.csp", "Content-Security-Policy set", "");
        }
        if (r.hasHeader("content-security-policy-report-only")) {
            return Finding.warn(ID, "headers.csp.report-only", LOW, "CSP is report-only",
                    "The policy is monitored but not enforced.",
                    "Move to an enforced Content-Security-Policy once reports are clean.");
        }
        return Finding.warn(ID, "headers.csp.missing", MEDIUM, "Content-Security-Policy missing",
                "No CSP limits where scripts can load from, so an injected script runs freely.",
                "Start with a report-only policy, then enforce it.");
    }

    private Finding framing(HttpExchange r) {
        String xfo = r.header("x-frame-options").orElse("").toUpperCase(Locale.ROOT);
        String csp = r.joinedHeader("content-security-policy").orElse("").toLowerCase(Locale.ROOT);
        if (csp.contains("frame-ancestors") || xfo.equals("DENY") || xfo.equals("SAMEORIGIN")) {
            return Finding.pass(ID, "headers.framing", "Clickjacking protection set",
                    csp.contains("frame-ancestors") ? "CSP frame-ancestors" : "X-Frame-Options: " + xfo);
        }
        return Finding.warn(ID, "headers.framing.missing", MEDIUM, "Page can be framed by any site",
                "Neither X-Frame-Options nor CSP frame-ancestors is set, which allows clickjacking.",
                "Send 'Content-Security-Policy: frame-ancestors 'self'' or 'X-Frame-Options: SAMEORIGIN'.");
    }

    private Finding nosniff(HttpExchange r) {
        if ("nosniff".equalsIgnoreCase(r.header("x-content-type-options").orElse("").strip())) {
            return Finding.pass(ID, "headers.nosniff", "X-Content-Type-Options: nosniff", "");
        }
        return Finding.warn(ID, "headers.nosniff.missing", LOW, "X-Content-Type-Options missing",
                "Browsers may guess content types, which can turn an upload into executable script.",
                "Send 'X-Content-Type-Options: nosniff'.");
    }

    private Finding referrerPolicy(HttpExchange r) {
        if (r.hasHeader("referrer-policy")) {
            return Finding.pass(ID, "headers.referrer-policy", "Referrer-Policy set", r.header("referrer-policy").orElse(""));
        }
        return Finding.warn(ID, "headers.referrer-policy.missing", LOW, "Referrer-Policy missing",
                "Full URLs, including query strings, may leak to other sites in the Referer header.",
                "Send 'Referrer-Policy: strict-origin-when-cross-origin'.");
    }

    private Optional<Finding> versionDisclosure(HttpExchange r) {
        for (String name : List.of("server", "x-powered-by", "x-aspnet-version")) {
            Optional<String> value = r.header(name);
            if (value.isPresent() && VERSION.matcher(value.get()).find()) {
                return Optional.of(Finding.warn(ID, "headers.version-disclosure", LOW,
                        "Server version disclosed in " + name,
                        name + ": " + value.get() + " tells attackers which known vulnerabilities to try.",
                        "Remove the version from the " + name + " header."));
            }
        }
        return Optional.empty();
    }
}
