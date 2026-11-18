package dev.vardaan.edgeprobe.core.net;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * One HTTP request and the response headers it got back. Bodies are never read: every check
 * works from status and headers, so the prober closes the stream as soon as headers arrive.
 *
 * @param uri           the URL requested
 * @param status        HTTP status code
 * @param httpVersion   "HTTP/1.1" or "HTTP/2"
 * @param headers       response headers, names lower-cased
 * @param elapsedMillis time from sending the request to receiving response headers
 */
public record HttpExchange(URI uri, int status, String httpVersion,
                           Map<String, List<String>> headers, long elapsedMillis) {

    public HttpExchange {
        Map<String, List<String>> normalized = new LinkedHashMap<>();
        headers.forEach((name, values) ->
                normalized.merge(name.toLowerCase(Locale.ROOT), List.copyOf(values), (a, b) -> {
                    var merged = new java.util.ArrayList<>(a);
                    merged.addAll(b);
                    return List.copyOf(merged);
                }));
        headers = Map.copyOf(normalized);
    }

    /** First value of a header, if present. */
    public Optional<String> header(String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values == null || values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
    }

    /** All values of a header joined with ", " (how HTTP defines repeated headers). */
    public Optional<String> joinedHeader(String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values == null || values.isEmpty() ? Optional.empty() : Optional.of(String.join(", ", values));
    }

    public boolean hasHeader(String name) {
        return headers.containsKey(name.toLowerCase(Locale.ROOT));
    }

    public boolean isRedirect() {
        return status >= 300 && status < 400 && status != 304 && hasHeader("location");
    }

    /** The redirect target resolved against this request's URL. */
    public Optional<URI> location() {
        if (!isRedirect()) {
            return Optional.empty();
        }
        try {
            return Optional.of(uri.resolve(header("location").orElseThrow().strip()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
