package dev.vardaan.edgeprobe.core.net;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A validated, normalized scan target: a host plus a path and query.
 *
 * <p>The scheme the user typed is deliberately not kept. Every scan probes the site over both
 * HTTPS and plain HTTP, because "does http:// redirect to https://" is one of the checks.
 * Explicit ports, credentials in the URL and non-http schemes are rejected, which narrows what
 * the scanner can be pointed at.
 *
 * @param host        lower-case host name or IP literal, without brackets or a trailing dot
 * @param pathAndQuery path (always starting with "/") plus "?query" when present
 */
public record TargetUrl(String host, String pathAndQuery) {

    private static final Pattern HOST_NAME = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    public static TargetUrl parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidTargetException("URL is empty");
        }
        String input = raw.strip();
        if (!input.contains("://")) {
            input = "https://" + input;
        }

        URI uri;
        try {
            uri = new URI(input);
        } catch (URISyntaxException e) {
            throw new InvalidTargetException("Not a valid URL: " + e.getReason());
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new InvalidTargetException("Only http and https URLs can be scanned, got '" + scheme + "'");
        }
        if (uri.getRawUserInfo() != null) {
            throw new InvalidTargetException("URLs with credentials are not allowed");
        }
        if (uri.getPort() != -1 && uri.getPort() != 80 && uri.getPort() != 443) {
            throw new InvalidTargetException("Custom ports are not supported; edgeprobe scans ports 80 and 443");
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new InvalidTargetException("URL has no host");
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        } else {
            if (host.endsWith(".")) {
                host = host.substring(0, host.length() - 1);
            }
            if (!HOST_NAME.matcher(host).matches() && !IPV4.matcher(host).matches()) {
                throw new InvalidTargetException("Not a valid host name: " + host);
            }
        }

        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        return new TargetUrl(host, path + query);
    }

    /** The URL for one scheme, using a port only when it differs from the scheme default. */
    public URI uri(String scheme, int port) {
        boolean defaultPort = (scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80);
        String authority = (host.contains(":") ? "[" + host + "]" : host) + (defaultPort ? "" : ":" + port);
        return URI.create(scheme + "://" + authority + pathAndQuery);
    }

    /** Canonical form used as the cache key and stored URL. */
    public String canonical() {
        return uri("https", 443).toString();
    }

    @Override
    public String toString() {
        return canonical();
    }
}
