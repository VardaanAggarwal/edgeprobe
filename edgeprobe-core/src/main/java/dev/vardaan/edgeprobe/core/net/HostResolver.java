package dev.vardaan.edgeprobe.core.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;

/** Resolves a host and enforces the {@link AddressPolicy} on every address it returns. */
public final class HostResolver {

    private final DnsResolver dns;
    private final AddressPolicy policy;

    public HostResolver(DnsResolver dns, AddressPolicy policy) {
        this.dns = dns;
        this.policy = policy;
    }

    /**
     * @throws UnresolvableHostException if DNS returns nothing
     * @throws BlockedTargetException    if ANY returned address is blocked. Checking only the first
     *                                   would let a name with one public and one private record
     *                                   through, since the client may connect to either.
     */
    public ResolvedHost resolve(String host) {
        long start = System.nanoTime();
        InetAddress[] addresses;
        try {
            addresses = dns.resolve(host);
        } catch (UnknownHostException e) {
            throw new UnresolvableHostException("Host does not resolve: " + host);
        }
        long millis = (System.nanoTime() - start) / 1_000_000;
        if (addresses == null || addresses.length == 0) {
            throw new UnresolvableHostException("Host does not resolve: " + host);
        }
        for (InetAddress address : addresses) {
            Optional<String> reason = policy.blockReason(address);
            if (reason.isPresent()) {
                throw new BlockedTargetException(
                        host + " resolves to " + address.getHostAddress() + ", a " + reason.get());
            }
        }
        return new ResolvedHost(host, List.of(addresses), millis);
    }

    public record ResolvedHost(String host, List<InetAddress> addresses, long lookupMillis) {
        public ResolvedHost {
            addresses = List.copyOf(addresses);
        }
    }
}
