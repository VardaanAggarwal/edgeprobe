package dev.vardaan.edgeprobe.core.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AddressPolicyTest {

    private final AddressPolicy policy = AddressPolicy.publicOnly();

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "0.0.0.0", "0.1.2.3", "100.64.0.1", "198.18.0.1", "224.0.0.1", "255.255.255.255",
            "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "::127.0.0.1", "ff02::1"})
    void blocksNonPublicAddresses(String ip) throws UnknownHostException {
        assertThat(policy.blockReason(InetAddress.getByName(ip))).as(ip).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {"93.184.215.14", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111"})
    void allowsPublicAddresses(String ip) throws UnknownHostException {
        assertThat(policy.blockReason(InetAddress.getByName(ip))).as(ip).isEmpty();
    }

    @Test
    void allowAllPermitsLoopbackForLocalDevelopment() throws UnknownHostException {
        assertThat(AddressPolicy.allowAll().blockReason(InetAddress.getByName("127.0.0.1"))).isEmpty();
    }

    @Test
    void resolverBlocksWhenAnyRecordIsPrivate() {
        DnsResolver dns = host -> new InetAddress[]{
                InetAddress.getByName("93.184.215.14"), InetAddress.getByName("10.0.0.5")};
        HostResolver resolver = new HostResolver(dns, policy);

        assertThatThrownBy(() -> resolver.resolve("mixed.example"))
                .isInstanceOf(BlockedTargetException.class)
                .hasMessageContaining("10.0.0.5");
    }

    @Test
    void resolverReportsUnresolvableHosts() {
        HostResolver resolver = new HostResolver(host -> {
            throw new UnknownHostException(host);
        }, policy);

        assertThatThrownBy(() -> resolver.resolve("nope.invalid")).isInstanceOf(UnresolvableHostException.class);
    }
}
