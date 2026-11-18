package dev.vardaan.edgeprobe.core.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Optional;

/**
 * Decides which IP addresses the scanner may connect to.
 *
 * <p>A scanner that fetches any URL a user submits is a server-side request forgery (SSRF)
 * risk: a user could make it call {@code http://169.254.169.254/} (the cloud metadata
 * service) or an internal admin panel. {@link #publicOnly()} blocks every non-public range.
 * The check runs on the resolved addresses, not the host name, so a public-looking name
 * that points at 10.0.0.5 is still blocked. It runs again on every redirect hop.
 */
public final class AddressPolicy {

    private final boolean allowNonPublic;

    private AddressPolicy(boolean allowNonPublic) {
        this.allowNonPublic = allowNonPublic;
    }

    /** Production policy: public unicast addresses only. */
    public static AddressPolicy publicOnly() {
        return new AddressPolicy(false);
    }

    /** For tests and local development only: allows loopback and private targets. */
    public static AddressPolicy allowAll() {
        return new AddressPolicy(true);
    }

    public boolean allowsNonPublic() {
        return allowNonPublic;
    }

    /** Returns why the address is blocked, or empty if the scanner may connect to it. */
    public Optional<String> blockReason(InetAddress address) {
        if (allowNonPublic) {
            return Optional.empty();
        }
        return nonPublicReason(address);
    }

    static Optional<String> nonPublicReason(InetAddress a) {
        if (a.isAnyLocalAddress()) {
            return Optional.of("unspecified address");
        }
        if (a.isLoopbackAddress()) {
            return Optional.of("loopback address");
        }
        if (a.isLinkLocalAddress()) {
            return Optional.of("link-local address (this range includes cloud metadata services)");
        }
        if (a.isSiteLocalAddress()) {
            return Optional.of("private network address");
        }
        if (a.isMulticastAddress()) {
            return Optional.of("multicast address");
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            int b0 = b[0] & 0xFF;
            int b1 = b[1] & 0xFF;
            if (b0 == 0) {
                return Optional.of("reserved 'this network' address");
            }
            if (b0 == 100 && (b1 & 0xC0) == 64) {
                return Optional.of("carrier-grade NAT address");
            }
            if (b0 == 198 && (b1 == 18 || b1 == 19)) {
                return Optional.of("benchmarking address");
            }
            if (b0 >= 240) {
                return Optional.of("reserved address");
            }
        }
        if (a instanceof Inet6Address) {
            int b0 = b[0] & 0xFF;
            if ((b0 & 0xFE) == 0xFC) {
                return Optional.of("IPv6 unique local address");
            }
            if (isIpv4Embedded(b)) {
                return Optional.of("IPv6 address embedding an IPv4 address");
            }
        }
        return Optional.empty();
    }

    /** ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible) can smuggle a private IPv4 address. */
    private static boolean isIpv4Embedded(byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        boolean mapped = (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
        boolean compatible = b[10] == 0 && b[11] == 0;
        return mapped || compatible;
    }
}
