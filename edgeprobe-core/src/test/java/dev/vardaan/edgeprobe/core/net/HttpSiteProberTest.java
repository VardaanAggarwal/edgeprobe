package dev.vardaan.edgeprobe.core.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Runs the real prober against local HTTP and HTTPS servers. The HTTPS server uses a
 * self-signed certificate for "localhost" (src/test/resources/tls/localhost.p12).
 */
class HttpSiteProberTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private HttpServer http;
    private HttpsServer https;
    private ExecutorService executor;
    private ExecutorService serverThreads;
    private SSLContext trustingClient;
    private final AtomicInteger conditionalHits = new AtomicInteger();
    private volatile HttpHandler httpsHandler;

    @BeforeEach
    void startServers() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = getClass().getResourceAsStream("/tls/localhost.p12")) {
            keyStore.load(in, PASSWORD);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("localhost", keyStore.getCertificate("localhost"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        trustingClient = SSLContext.getInstance("TLS");
        trustingClient.init(null, tmf.getTrustManagers(), null);

        InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        https = HttpsServer.create(loopback, 0);
        https.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        httpsHandler = this::wellConfiguredPage;
        https.createContext("/", ex -> httpsHandler.handle(ex));
        // The JDK server handles connections on one thread by default; a slow handler would then
        // also block the TLS probe's handshake and make timeout tests flaky.
        serverThreads = Executors.newCachedThreadPool();
        https.setExecutor(serverThreads);
        https.start();

        http = HttpServer.create(loopback, 0);
        http.createContext("/", ex -> {
            ex.getResponseHeaders().add("Location", "https://localhost:" + https.getAddress().getPort() + ex.getRequestURI());
            respond(ex, 301, "");
        });
        http.createContext("/loop", ex -> {
            ex.getResponseHeaders().add("Location", "/loop");
            respond(ex, 302, "");
        });
        http.setExecutor(serverThreads);
        http.start();

        executor = Executors.newFixedThreadPool(6);
    }

    @AfterEach
    void stopServers() {
        http.stop(0);
        https.stop(0);
        executor.shutdownNow();
        serverThreads.shutdownNow();
    }

    private void wellConfiguredPage(HttpExchange ex) throws IOException {
        String etag = "\"v1\"";
        if (etag.equals(ex.getRequestHeaders().getFirst("If-None-Match"))) {
            conditionalHits.incrementAndGet();
            ex.getResponseHeaders().add("ETag", etag);
            ex.sendResponseHeaders(304, -1);
            ex.close();
            return;
        }
        ex.getResponseHeaders().add("Content-Type", "text/html");
        ex.getResponseHeaders().add("ETag", etag);
        ex.getResponseHeaders().add("Cache-Control", "no-cache");
        ex.getResponseHeaders().add("Strict-Transport-Security", "max-age=31536000");
        respond(ex, 200, "<html>hello</html>");
    }

    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        }
        ex.close();
    }

    private ProberConfig config(SSLContext clientContext) {
        return ProberConfig.defaults()
                .withPolicy(AddressPolicy.allowAll())
                .withPorts(http.getAddress().getPort(), https.getAddress().getPort())
                .withSslContext(clientContext)
                .withTimeouts(Duration.ofSeconds(2), Duration.ofSeconds(2), Duration.ofSeconds(4));
    }

    @Test
    void collectsRedirectsHeadersTlsAndRevalidation() {
        HttpSiteProber prober = new HttpSiteProber(config(trustingClient), executor);

        SiteSnapshot s = prober.probe(TargetUrl.parse("localhost/"));

        assertThat(s.errors()).isEmpty();
        assertThat(s.httpChain()).hasSize(2);
        assertThat(s.httpChain().get(0).status()).isEqualTo(301);
        assertThat(s.httpChain().get(1).uri().getScheme()).isEqualTo("https");
        assertThat(s.finalHttps()).hasValueSatisfying(r -> {
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.header("strict-transport-security")).hasValue("max-age=31536000");
        });
        assertThat(s.tls().trusted()).isTrue();
        assertThat(s.tls().protocol()).startsWith("TLSv1.");
        assertThat(s.tls().leaf()).hasValueSatisfying(c -> {
            assertThat(c.subject()).isEqualTo("CN=localhost");
            assertThat(c.subjectAltNames()).contains("localhost");
            assertThat(c.keyAlgorithm()).isEqualTo("EC");
        });
        assertThat(s.revalidation().status()).isEqualTo(304);
        assertThat(conditionalHits).hasValue(1);
    }

    @Test
    void untrustedCertificateIsInspectedButReportedAsUntrusted() throws Exception {
        HttpSiteProber prober = new HttpSiteProber(config(SSLContext.getDefault()), executor);

        SiteSnapshot s = prober.probe(TargetUrl.parse("localhost/"));

        assertThat(s.tls().trusted()).isFalse();
        assertThat(s.tls().handshakeError()).contains("trusted root");
        assertThat(s.tls().leaf()).hasValueSatisfying(c -> assertThat(c.selfSigned()).isTrue());
        assertThat(s.httpsChain()).isEmpty();
        assertThat(s.errors()).containsKey("https");
    }

    @Test
    void redirectLoopIsCutOffAtTheLimit() {
        HttpSiteProber prober = new HttpSiteProber(config(trustingClient).withMaxRedirects(3), executor);

        SiteSnapshot s = prober.probe(TargetUrl.parse("localhost/loop"));

        assertThat(s.redirectLoop()).isTrue();
        assertThat(s.httpChain()).hasSize(4);
        assertThat(s.errors().get("http")).contains("stopped after 3 redirects");
    }

    @Test
    void slowProbeTimesOutWithoutLosingTheOthers() {
        httpsHandler = ex -> {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(ex, 200, "late");
        };
        ProberConfig config = config(trustingClient)
                .withTimeouts(Duration.ofSeconds(1), Duration.ofSeconds(10), Duration.ofMillis(1500));
        HttpSiteProber prober = new HttpSiteProber(config, executor);

        long start = System.nanoTime();
        SiteSnapshot s = prober.probe(TargetUrl.parse("localhost/"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMs).isLessThan(3_000);
        assertThat(s.errors().get("https")).contains("timed out");
        assertThat(s.tls()).isNotNull();
        assertThat(s.httpChain()).isNotEmpty();
    }

    @Test
    void constructsWithProductionDefaults() {
        // Regression: ports 80/443 appeared twice in the allowed-port set and Set.of threw.
        new HttpSiteProber(ProberConfig.defaults(), executor);
    }

    @Test
    void publicOnlyPolicyRefusesLoopbackBeforeAnyRequest() {
        ProberConfig config = config(trustingClient).withPolicy(AddressPolicy.publicOnly());
        HttpSiteProber prober = new HttpSiteProber(config, executor);

        assertThatThrownBy(() -> prober.probe(TargetUrl.parse("localhost/")))
                .isInstanceOf(BlockedTargetException.class)
                .hasMessageContaining("loopback");
        assertThat(conditionalHits).hasValue(0);
    }
}
