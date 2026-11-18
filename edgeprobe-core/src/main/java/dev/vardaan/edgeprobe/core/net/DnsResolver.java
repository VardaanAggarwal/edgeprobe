package dev.vardaan.edgeprobe.core.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Seam over DNS so tests can resolve names without the network. */
@FunctionalInterface
public interface DnsResolver {

    DnsResolver SYSTEM = InetAddress::getAllByName;

    InetAddress[] resolve(String host) throws UnknownHostException;
}
