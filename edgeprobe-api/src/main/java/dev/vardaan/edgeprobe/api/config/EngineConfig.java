package dev.vardaan.edgeprobe.api.config;

import dev.vardaan.edgeprobe.core.check.Checks;
import dev.vardaan.edgeprobe.core.engine.ScanEngine;
import dev.vardaan.edgeprobe.core.net.AddressPolicy;
import dev.vardaan.edgeprobe.core.net.HttpSiteProber;
import dev.vardaan.edgeprobe.core.net.Prober;
import dev.vardaan.edgeprobe.core.net.ProberConfig;
import java.time.Clock;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Wires the framework-free core engine into Spring. */
@Configuration(proxyBeanMethods = false)
public class EngineConfig {

    private static final Logger log = LoggerFactory.getLogger(EngineConfig.class);

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean(destroyMethod = "shutdownNow")
    ExecutorService probeExecutor(EdgeprobeProperties properties) {
        AtomicInteger counter = new AtomicInteger();
        ThreadFactory threads = runnable -> {
            Thread thread = new Thread(runnable, "probe-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        return Executors.newFixedThreadPool(properties.probe().threads(), threads);
    }

    @Bean
    Prober prober(EdgeprobeProperties properties, ExecutorService probeExecutor) {
        EdgeprobeProperties.Probe probe = properties.probe();
        if (probe.allowPrivateTargets()) {
            log.warn("edgeprobe.probe.allow-private-targets=true: scans can reach private networks. "
                    + "Use only for local development.");
        }
        ProberConfig config = ProberConfig.defaults()
                .withTimeouts(probe.connectTimeout(), probe.requestTimeout(), probe.overallTimeout())
                .withMaxRedirects(probe.maxRedirects())
                .withPolicy(probe.allowPrivateTargets() ? AddressPolicy.allowAll() : AddressPolicy.publicOnly());
        return new HttpSiteProber(config, probeExecutor);
    }

    @Bean
    ScanEngine scanEngine(Prober prober, Clock clock) {
        return new ScanEngine(prober, Checks.defaults(clock), clock);
    }
}
