package dev.vardaan.edgeprobe.api.ratelimit;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * Classic token bucket. Holds up to {@code capacity} tokens and gains one every
 * {@code refillPeriod}; each request spends one. Allows short bursts while capping the
 * long-run rate. Refill is computed lazily from elapsed time, so there is no background thread.
 *
 * <p>State is kept as integer nanoseconds of "credit" (one token = {@code refillPeriod} of credit)
 * rather than a fractional token count, so the arithmetic is exact and the reported wait is precise.
 */
public final class TokenBucket {

    private final long periodNanos;
    private final long maxCredit;
    private final LongSupplier nanoClock;
    private long credit;
    private long lastRefill;

    public TokenBucket(int capacity, Duration refillPeriod, LongSupplier nanoClock) {
        if (capacity < 1 || refillPeriod.isZero() || refillPeriod.isNegative()) {
            throw new IllegalArgumentException("capacity must be >= 1 and refillPeriod positive");
        }
        this.periodNanos = refillPeriod.toNanos();
        this.maxCredit = Math.multiplyExact(periodNanos, capacity);
        this.nanoClock = nanoClock;
        this.credit = maxCredit;
        this.lastRefill = nanoClock.getAsLong();
    }

    /**
     * Spends one token if available.
     *
     * @return 0 if the request is allowed, otherwise nanoseconds until a token will be available
     */
    public synchronized long tryConsume() {
        long now = nanoClock.getAsLong();
        long elapsed = Math.max(0, now - lastRefill);
        credit = elapsed >= maxCredit - credit ? maxCredit : credit + elapsed;
        lastRefill = now;
        if (credit >= periodNanos) {
            credit -= periodNanos;
            return 0;
        }
        return periodNanos - credit;
    }

    public synchronized int available() {
        return (int) (credit / periodNanos);
    }
}
