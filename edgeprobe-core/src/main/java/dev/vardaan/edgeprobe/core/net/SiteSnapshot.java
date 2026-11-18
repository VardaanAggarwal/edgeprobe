package dev.vardaan.edgeprobe.core.net;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Everything the prober observed about a site. Checks are pure functions of a snapshot: all
 * network I/O happens once, in the prober, and the checks only read this record. That split is
 * what makes each check unit-testable without a network.
 *
 * <p>A snapshot can be partial. If one probe fails or times out, its field is empty and
 * {@link #errors()} says why; the other probes still count.
 *
 * @param target           what was scanned
 * @param addresses        resolved IP addresses
 * @param dnsMillis        DNS lookup time
 * @param httpsChain       requests made starting at https://, following redirects, in order
 * @param httpChain        the same starting at http://
 * @param redirectLoop     true if either chain stopped because it hit the redirect limit
 * @param tls              TLS handshake details, or null if the handshake probe failed
 * @param revalidation     a conditional re-request of the final HTTPS URL, or null if not sent
 * @param errors           probe name ("https", "http", "tls", "revalidation") to error message
 */
public record SiteSnapshot(TargetUrl target, List<String> addresses, long dnsMillis,
                           List<HttpExchange> httpsChain, List<HttpExchange> httpChain,
                           boolean redirectLoop, TlsInfo tls, HttpExchange revalidation,
                           Map<String, String> errors) {

    public SiteSnapshot {
        addresses = List.copyOf(addresses);
        httpsChain = List.copyOf(httpsChain);
        httpChain = List.copyOf(httpChain);
        errors = Map.copyOf(errors);
    }

    /** The last HTTPS response, if it is a real response rather than a redirect. */
    public Optional<HttpExchange> finalHttps() {
        if (httpsChain.isEmpty()) {
            return Optional.empty();
        }
        HttpExchange last = httpsChain.get(httpsChain.size() - 1);
        return last.isRedirect() ? Optional.empty() : Optional.of(last);
    }

    /**
     * True when the final HTTPS response is a real 2xx page. A 403 from bot protection or a 5xx
     * error page does not describe the site, so header checks skip it and the grade is withheld.
     */
    public boolean hasUsablePage() {
        return finalHttps().map(r -> r.status() >= 200 && r.status() < 300).orElse(false);
    }

    public Optional<TlsInfo> tlsInfo() {
        return Optional.ofNullable(tls);
    }

    public Optional<HttpExchange> revalidationExchange() {
        return Optional.ofNullable(revalidation);
    }

    public Optional<String> error(String probe) {
        return Optional.ofNullable(errors.get(probe));
    }
}
