package dev.vardaan.edgeprobe.core.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Probes a site over the network.
 *
 * <p>After one DNS lookup (checked against the address policy), three independent probes run
 * in parallel on the supplied executor: the HTTPS redirect chain, the plain-HTTP redirect chain,
 * and a TLS handshake. When the HTTPS chain finishes, a conditional request tests cache
 * revalidation. The whole probe has one deadline; a probe still running at the deadline is
 * cancelled and reported as timed out, and the rest of the snapshot is kept.
 */
public final class HttpSiteProber implements Prober {

    private final ProberConfig config;
    private final HostResolver resolver;
    private final TlsInspector tlsInspector;
    private final Executor executor;
    private final HttpClient client;
    private final Set<Integer> allowedPorts;

    /**
     * @param executor runs the parallel probes. The caller owns its lifecycle. Each scan uses up to
     *                 three threads at once, so size it as 3 x expected concurrent scans.
     */
    public HttpSiteProber(ProberConfig config, Executor executor) {
        this.config = config;
        this.resolver = new HostResolver(config.dns(), config.policy());
        this.tlsInspector = new TlsInspector(config);
        this.executor = executor;
        this.client = HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(config.sslContext())
                .version(HttpClient.Version.HTTP_2)
                .build();
        // Set.of rejects duplicates, and in production httpPort/httpsPort ARE 80/443.
        this.allowedPorts = Set.copyOf(java.util.List.of(80, 443, config.httpPort(), config.httpsPort()));
    }

    @Override
    public SiteSnapshot probe(TargetUrl target) {
        HostResolver.ResolvedHost resolved = resolver.resolve(target.host());
        long deadline = System.nanoTime() + config.overallTimeout().toNanos();
        Map<String, String> errors = new ConcurrentHashMap<>();

        // Hops are appended as they complete, so a chain cut off by the deadline keeps the hops it finished.
        List<HttpExchange> httpsHops = new CopyOnWriteArrayList<>();
        List<HttpExchange> httpHops = new CopyOnWriteArrayList<>();
        CompletableFuture<Chain> https = CompletableFuture.supplyAsync(
                () -> followChain(target.uri("https", config.httpsPort()), httpsHops), executor);
        CompletableFuture<Chain> http = CompletableFuture.supplyAsync(
                () -> followChain(target.uri("http", config.httpPort()), httpHops), executor);
        CompletableFuture<TlsInfo> tls = CompletableFuture.supplyAsync(() -> {
            try {
                return tlsInspector.inspect(target.host(), resolved.addresses().get(0), config.httpsPort());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }, executor);
        CompletableFuture<Optional<HttpExchange>> revalidation =
                https.thenApplyAsync(chain -> revalidate(httpsHops), executor);

        Chain httpsChain = await("https", https, deadline, errors);
        Chain httpChain = await("http", http, deadline, errors);
        TlsInfo tlsInfo = await("tls", tls, deadline, errors);
        Optional<HttpExchange> reval = httpsChain == null ? Optional.empty()
                : Optional.ofNullable(await("revalidation", revalidation, deadline, errors)).flatMap(o -> o);

        recordPartialChain("https", httpsChain, errors);
        recordPartialChain("http", httpChain, errors);

        return new SiteSnapshot(
                target,
                resolved.addresses().stream().map(java.net.InetAddress::getHostAddress).toList(),
                resolved.lookupMillis(),
                List.copyOf(httpsHops),
                List.copyOf(httpHops),
                (httpsChain != null && httpsChain.loop()) || (httpChain != null && httpChain.loop()),
                tlsInfo,
                reval.orElse(null),
                errors);
    }

    private static void recordPartialChain(String name, Chain chain, Map<String, String> errors) {
        if (chain != null && chain.error() != null) {
            errors.putIfAbsent(name, chain.error());
        }
    }

    private <T> T await(String name, CompletableFuture<T> future, long deadlineNanos, Map<String, String> errors) {
        long remaining = deadlineNanos - System.nanoTime();
        try {
            return future.get(Math.max(0, remaining), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            errors.put(name, "timed out after " + config.overallTimeout().toSeconds() + "s");
        } catch (ExecutionException e) {
            errors.put(name, Errors.describe(e));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            errors.put(name, "interrupted");
        }
        return null;
    }

    /** Follows redirects manually so every hop can be recorded and checked against the address policy. */
    private Chain followChain(URI start, List<HttpExchange> hops) {
        URI current = start;
        for (int i = 0; i <= config.maxRedirects(); i++) {
            if (i > 0) {
                try {
                    checkRedirectTarget(current);
                } catch (TargetException e) {
                    return new Chain(false, "redirect to " + current + " not followed: " + e.getMessage());
                }
            }
            HttpExchange exchange;
            try {
                exchange = send(current, Map.of());
            } catch (IOException e) {
                if (hops.isEmpty()) {
                    throw new UncheckedIOException(e);
                }
                return new Chain(false, "request to " + current + " failed: " + Errors.describe(e));
            }
            hops.add(exchange);
            Optional<URI> next = exchange.location();
            if (next.isEmpty()) {
                return new Chain(false, null);
            }
            current = next.get();
        }
        return new Chain(true, "stopped after " + config.maxRedirects() + " redirects");
    }

    private void checkRedirectTarget(URI uri) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new InvalidTargetException("unsupported scheme '" + scheme + "'");
        }
        if (uri.getHost() == null) {
            throw new InvalidTargetException("no host");
        }
        if (uri.getPort() != -1 && !allowedPorts.contains(uri.getPort())) {
            throw new BlockedTargetException("port " + uri.getPort() + " is not allowed");
        }
        String host = uri.getHost();
        if (host.startsWith("[")) {
            host = host.substring(1, host.length() - 1);
        }
        resolver.resolve(host);
    }

    /** Re-requests the final HTTPS URL with its validator, to see whether the server answers 304. */
    private Optional<HttpExchange> revalidate(List<HttpExchange> hops) {
        if (hops.isEmpty()) {
            return Optional.empty();
        }
        HttpExchange last = hops.get(hops.size() - 1);
        if (last.isRedirect() || last.status() < 200 || last.status() >= 300) {
            return Optional.empty();
        }
        Optional<String> etag = last.header("etag");
        Optional<String> lastModified = last.header("last-modified");
        Map<String, String> conditional;
        if (etag.isPresent()) {
            conditional = Map.of("If-None-Match", etag.get());
        } else if (lastModified.isPresent()) {
            conditional = Map.of("If-Modified-Since", lastModified.get());
        } else {
            return Optional.empty();
        }
        try {
            return Optional.of(send(last.uri(), conditional));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private HttpExchange send(URI uri, Map<String, String> extraHeaders) throws IOException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(config.requestTimeout())
                .header("User-Agent", config.userAgent())
                .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
                .header("Accept-Encoding", "br, gzip, zstd");
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            // Avoid an h2c upgrade attempt on plain HTTP; some servers mishandle it.
            request.version(HttpClient.Version.HTTP_1_1);
        }
        extraHeaders.forEach(request::header);

        long start = System.nanoTime();
        HttpResponse<InputStream> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        // Checks only need headers. Closing now avoids downloading (possibly endless) bodies.
        response.body().close();
        String version = response.version() == HttpClient.Version.HTTP_2 ? "HTTP/2" : "HTTP/1.1";
        return new HttpExchange(uri, response.statusCode(), version, response.headers().map(), elapsedMillis);
    }

    /** How a chain ended; the hops themselves are in the list passed to followChain. */
    private record Chain(boolean loop, String error) {
    }
}
