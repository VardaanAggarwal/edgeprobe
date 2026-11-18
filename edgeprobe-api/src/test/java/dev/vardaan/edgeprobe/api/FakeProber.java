package dev.vardaan.edgeprobe.api;

import dev.vardaan.edgeprobe.core.net.AddressPolicy;
import dev.vardaan.edgeprobe.core.net.HostResolver;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.Prober;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import dev.vardaan.edgeprobe.core.net.TargetUrl;
import dev.vardaan.edgeprobe.core.net.TlsInfo;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stands in for the network. It still runs the real {@link HostResolver} with the production
 * public-only policy, over a fake DNS table, so SSRF blocking is exercised end to end:
 * {@code *.internal.example} resolves to 10.0.0.7 and {@code *.missing.example} does not resolve.
 */
public class FakeProber implements Prober {

    private final HostResolver resolver = new HostResolver(FakeProber::dns, AddressPolicy.publicOnly());
    private final Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
    private final Map<String, CountDownLatch> gates = new ConcurrentHashMap<>();

    private static InetAddress[] dns(String host) throws UnknownHostException {
        if (host.endsWith("missing.example")) {
            throw new UnknownHostException(host);
        }
        String ip = host.endsWith("internal.example") ? "10.0.0.7" : "93.184.215.14";
        return new InetAddress[]{InetAddress.getByName(ip)};
    }

    /** Makes probes of {@code host} block until the returned latch is counted down. */
    public CountDownLatch gate(String host) {
        CountDownLatch latch = new CountDownLatch(1);
        gates.put(host, latch);
        return latch;
    }

    public int calls(String host) {
        return calls.getOrDefault(host, new AtomicInteger()).get();
    }

    @Override
    public SiteSnapshot probe(TargetUrl target) {
        resolver.resolve(target.host());
        calls.computeIfAbsent(target.host(), h -> new AtomicInteger()).incrementAndGet();
        CountDownLatch gate = gates.get(target.host());
        if (gate != null) {
            try {
                gate.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return goodSite(target);
    }

    static SiteSnapshot goodSite(TargetUrl target) {
        String url = target.canonical();
        HttpExchange page = new HttpExchange(URI.create(url), 200, "HTTP/2", Map.of(
                "content-type", List.of("text/html"),
                "content-encoding", List.of("br"),
                "cache-control", List.of("no-cache"),
                "etag", List.of("\"v1\""),
                "strict-transport-security", List.of("max-age=31536000"),
                "content-security-policy", List.of("default-src 'self'; frame-ancestors 'none'"),
                "x-content-type-options", List.of("nosniff"),
                "referrer-policy", List.of("no-referrer")), 90);
        HttpExchange redirect = new HttpExchange(target.uri("http", 80), 301, "HTTP/1.1",
                Map.of("location", List.of(url)), 40);
        HttpExchange notModified = new HttpExchange(URI.create(url), 304, "HTTP/2", Map.of(), 50);
        Instant now = Instant.now();
        TlsInfo tls = new TlsInfo(true, null, "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(new TlsInfo.CertInfo(
                "CN=" + target.host(), "CN=Test CA", now.minusSeconds(86_400), now.plusSeconds(86_400 * 60),
                List.of(target.host()), "SHA256withECDSA", "EC", 256)));
        return new SiteSnapshot(target, List.of("93.184.215.14", "2606:2800::1"), 5, List.of(page),
                List.of(redirect, page), false, tls, notModified, Map.of());
    }
}
