package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.HIGH;
import static dev.vardaan.edgeprobe.core.model.Severity.LOW;
import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/** Plain HTTP should permanently redirect to HTTPS on the same host, without long chains or loops. */
public final class HttpsRedirectCheck implements Check {

    static final String ID = "https-redirect";
    static final int MAX_HOPS = 2;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "HTTP to HTTPS redirect: present, permanent, same host first, short chain, no loops";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        List<Finding> findings = new ArrayList<>();

        if (s.redirectLoop()) {
            findings.add(Finding.fail(ID, "redirect.loop", MEDIUM, "Redirect loop or overly long redirect chain",
                    s.error("https").or(() -> s.error("http")).orElse(""),
                    "Make each URL redirect at most once or twice to its final location."));
        }

        if (s.httpChain().isEmpty()) {
            findings.add(Finding.warn(ID, "redirect.http-unreachable", LOW, "Plain HTTP is not reachable",
                    "Port 80: " + s.error("http").orElse("no response"),
                    "Listen on port 80 and redirect to HTTPS, so visitors who type the bare domain still arrive."));
        } else {
            HttpExchange first = s.httpChain().get(0);
            if (!first.isRedirect() && first.status() >= 400) {
                findings.add(Finding.error(ID, "http:// responded " + first.status()
                        + " (usually bot protection), so the redirect could not be verified"));
            } else if (!first.isRedirect()) {
                findings.add(Finding.fail(ID, "redirect.missing", HIGH, "HTTP does not redirect to HTTPS",
                        "http:// returned " + first.status() + " without redirecting.",
                        "Return a 301 or 308 from every http:// URL to its https:// equivalent."));
            } else {
                findings.addAll(evaluateRedirect(s, first));
            }
        }

        int httpsHops = Math.max(0, s.httpsChain().size() - 1);
        if (httpsHops > MAX_HOPS) {
            findings.add(Finding.warn(ID, "redirect.chain-long", LOW, httpsHops + " redirects before content",
                    "Each redirect adds a round trip before the page can start loading.",
                    "Point links and redirects directly at the final URL."));
        }
        return findings;
    }

    private List<Finding> evaluateRedirect(SiteSnapshot s, HttpExchange first) {
        List<Finding> findings = new ArrayList<>();
        boolean reachesHttps = s.httpChain().stream().map(HttpExchange::uri).anyMatch(u -> "https".equals(u.getScheme()));
        if (!reachesHttps) {
            findings.add(Finding.fail(ID, "redirect.not-https", HIGH, "HTTP redirects, but never to HTTPS",
                    "The redirect chain from http:// stays on plain HTTP.",
                    "Redirect http:// URLs to https://."));
            return findings;
        }

        int status = first.status();
        if (status == 301 || status == 308) {
            findings.add(Finding.pass(ID, "redirect.permanent", "HTTP permanently redirects to HTTPS (" + status + ")", ""));
        } else {
            findings.add(Finding.warn(ID, "redirect.temporary", LOW, "HTTP to HTTPS redirect is temporary (" + status + ")",
                    "Browsers and caches will not remember a " + status + " redirect.",
                    "Use 301 or 308 for the HTTP to HTTPS redirect."));
        }

        URI target = first.location().orElseThrow();
        if (!s.target().host().equalsIgnoreCase(target.getHost())) {
            findings.add(Finding.warn(ID, "redirect.cross-host", LOW, "First redirect changes host",
                    "http://" + s.target().host() + " redirects to " + target + ".",
                    "Redirect to https:// on the same host first, so that host can set HSTS (required for HSTS preload)."));
        }
        return findings;
    }
}
