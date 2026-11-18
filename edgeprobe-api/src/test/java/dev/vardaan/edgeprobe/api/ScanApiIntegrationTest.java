package dev.vardaan.edgeprobe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.vardaan.edgeprobe.api.scan.ScanService;
import dev.vardaan.edgeprobe.api.scan.ScanService.CacheStatus;
import dev.vardaan.edgeprobe.api.scan.ScanService.ScanResult;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Full stack: HTTP layer, validation, service, cache, coalescing, rate limiting, JPA and Flyway
 * against PostgreSQL in Docker. Only the network prober is replaced.
 */
@SpringBootTest(properties = {"edgeprobe.rate-limit.capacity=3", "edgeprobe.rate-limit.refill-period=1h"})
@AutoConfigureMockMvc
@Import({TestcontainersConfiguration.class, ScanApiIntegrationTest.FakeProberConfig.class})
class ScanApiIntegrationTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class FakeProberConfig {
        @Bean
        @Primary
        FakeProber fakeProber() {
            return new FakeProber();
        }
    }

    /** Each request gets its own client IP so the rate limiter only bites in the test that targets it. */
    private static final AtomicInteger NEXT_IP = new AtomicInteger(1);

    @Autowired
    MockMvc mvc;

    @Autowired
    FakeProber prober;

    @Autowired
    ScanService scanService;

    private ResultActions scan(String body) throws Exception {
        return scanFrom("198.51.100." + NEXT_IP.getAndIncrement() % 250, body);
    }

    private ResultActions scanFrom(String ip, String body) throws Exception {
        return mvc.perform(post("/api/v1/scans")
                .with(request -> {
                    request.setRemoteAddr(ip);
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static String id(MvcResult result) throws Exception {
        return JsonPath.read(result.getResponse().getContentAsString(), "$.id");
    }

    @Test
    void createsAScanThenServesItById() throws Exception {
        MvcResult created = scan("{\"url\":\"Create.Example/path\"}")
                .andExpect(status().isCreated())
                .andExpect(header().string("X-Edgeprobe-Cache", "MISS"))
                .andExpect(jsonPath("$.url").value("https://create.example/path"))
                .andExpect(jsonPath("$.grade").value("A"))
                .andExpect(jsonPath("$.summary.fail").value(0))
                .andExpect(jsonPath("$.findings[0].checkId").value("tls"))
                .andReturn();
        String location = created.getResponse().getHeader("Location");

        mvc.perform(get(location))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id(created)))
                .andExpect(jsonPath("$.findings.length()").value(org.hamcrest.Matchers.greaterThan(10)));
    }

    @Test
    void repeatScanIsServedFromCacheUnlessFreshIsRequested() throws Exception {
        String first = id(scan("{\"url\":\"cache.example\"}").andExpect(status().isCreated()).andReturn());

        MvcResult second = scan("{\"url\":\"https://cache.example/\"}")
                .andExpect(status().isOk())
                .andExpect(header().string("X-Edgeprobe-Cache", "HIT"))
                .andReturn();
        assertThat(id(second)).isEqualTo(first);
        assertThat(prober.calls("cache.example")).isEqualTo(1);

        MvcResult fresh = scan("{\"url\":\"cache.example\",\"fresh\":true}")
                .andExpect(status().isCreated())
                .andReturn();
        assertThat(id(fresh)).isNotEqualTo(first);
        assertThat(prober.calls("cache.example")).isEqualTo(2);
    }

    @Test
    void concurrentScansOfOneUrlShareASingleProbe() throws Exception {
        CountDownLatch gate = prober.gate("burst.example");
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<ScanResult>> futures = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                futures.add(pool.submit(() -> scanService.scan("burst.example", true)));
            }
            Thread.sleep(300);
            gate.countDown();

            List<ScanResult> results = new ArrayList<>();
            for (Future<ScanResult> f : futures) {
                results.add(f.get());
            }
            assertThat(prober.calls("burst.example")).isEqualTo(1);
            assertThat(results).extracting(r -> r.scan().id()).containsOnly(results.get(0).scan().id());
            assertThat(results).filteredOn(r -> r.cacheStatus() == CacheStatus.MISS).hasSize(1);
            assertThat(results).filteredOn(r -> r.cacheStatus() == CacheStatus.COALESCED).hasSize(7);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void invalidUrlsAreRejectedAsProblemDetails() throws Exception {
        scan("{\"url\":\"ftp://example.com\"}")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Invalid URL"));

        scan("{\"url\":\"\"}").andExpect(status().isBadRequest());
    }

    @Test
    void privateNetworkTargetsAreBlocked() throws Exception {
        scan("{\"url\":\"admin.internal.example\"}")
                .andExpect(status().isUnprocessableContent())
                .andExpect(jsonPath("$.title").value("Target not allowed"))
                .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("10.0.0.7")));
    }

    @Test
    void unresolvableHostsAreReported() throws Exception {
        scan("{\"url\":\"nothing.missing.example\"}")
                .andExpect(status().isUnprocessableContent())
                .andExpect(jsonPath("$.title").value("Host does not resolve"));
    }

    @Test
    void unknownScanIdIs404() throws Exception {
        mvc.perform(get("/api/v1/scans/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Scan not found"));
    }

    @Test
    void historyIsPaginatedNewestFirst() throws Exception {
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            ids.add(id(scan("{\"url\":\"history.example\",\"fresh\":true}").andReturn()));
        }

        mvc.perform(get("/api/v1/scans").param("host", "history.example").param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(2))
                .andExpect(jsonPath("$.items[0].id").value(ids.get(2)))
                .andExpect(jsonPath("$.totalItems").value(3))
                .andExpect(jsonPath("$.totalPages").value(2));

        mvc.perform(get("/api/v1/scans").param("size", "500")).andExpect(status().isBadRequest());
    }

    @Test
    void rateLimitReturns429WithRetryAfter() throws Exception {
        String ip = "203.0.113.50";
        for (int i = 0; i < 3; i++) {
            scanFrom(ip, "{\"url\":\"ratelimit.example\"}").andExpect(status().is2xxSuccessful());
        }
        scanFrom(ip, "{\"url\":\"ratelimit.example\"}")
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.status").value(429));

        scanFrom("203.0.113.51", "{\"url\":\"ratelimit.example\"}").andExpect(status().isOk());
    }

    @Test
    void listsTheChecksEveryScanRuns() throws Exception {
        mvc.perform(get("/api/v1/checks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].id").value(org.hamcrest.Matchers.contains(
                        "tls", "https-redirect", "security-headers", "caching", "compression", "performance", "dns")));
    }

    @Test
    void healthEndpointIsUp() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
    }
}
