package dev.vardaan.edgeprobe.api.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class TokenBucketTest {

    private final AtomicLong now = new AtomicLong(0);

    @Test
    void allowsABurstUpToCapacityThenRejects() {
        TokenBucket bucket = new TokenBucket(3, Duration.ofSeconds(6), now::get);

        assertThat(bucket.tryConsume()).isZero();
        assertThat(bucket.tryConsume()).isZero();
        assertThat(bucket.tryConsume()).isZero();
        assertThat(bucket.tryConsume()).isEqualTo(Duration.ofSeconds(6).toNanos());
    }

    @Test
    void refillsOneTokenPerPeriodAndReportsTheWait() {
        TokenBucket bucket = new TokenBucket(1, Duration.ofSeconds(6), now::get);
        bucket.tryConsume();

        now.addAndGet(Duration.ofSeconds(4).toNanos());
        assertThat(bucket.tryConsume()).isEqualTo(Duration.ofSeconds(2).toNanos());

        now.addAndGet(Duration.ofSeconds(2).toNanos());
        assertThat(bucket.tryConsume()).isZero();
    }

    @Test
    void neverAccumulatesBeyondCapacity() {
        TokenBucket bucket = new TokenBucket(2, Duration.ofSeconds(1), now::get);
        now.addAndGet(Duration.ofHours(1).toNanos());

        assertThat(bucket.tryConsume()).isZero();
        assertThat(bucket.tryConsume()).isZero();
        assertThat(bucket.tryConsume()).isPositive();
    }

    @Test
    void concurrentCallersNeverOverspend() throws Exception {
        TokenBucket bucket = new TokenBucket(100, Duration.ofDays(1), now::get);
        AtomicInteger allowed = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        for (int i = 0; i < 1_000; i++) {
            pool.submit(() -> {
                if (bucket.tryConsume() == 0) {
                    allowed.incrementAndGet();
                }
            });
        }
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        assertThat(allowed).hasValue(100);
    }

    @Test
    void rejectsNonsenseConfiguration() {
        assertThatThrownBy(() -> new TokenBucket(0, Duration.ofSeconds(1), now::get))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
