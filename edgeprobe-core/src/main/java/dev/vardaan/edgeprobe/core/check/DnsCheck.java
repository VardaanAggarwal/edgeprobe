package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.LOW;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.ArrayList;
import java.util.List;

/** Resolved addresses and IPv6 reachability. */
public final class DnsCheck implements Check {

    static final String ID = "dns";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "Resolved addresses and IPv6 (AAAA) availability";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        List<Finding> findings = new ArrayList<>();
        findings.add(Finding.info(ID, "dns.resolved", "Resolves to " + s.addresses().size() + " address(es)",
                String.join(", ", s.addresses()) + " (" + s.dnsMillis() + " ms lookup)"));
        boolean ipv6 = s.addresses().stream().anyMatch(a -> a.contains(":"));
        if (ipv6) {
            findings.add(Finding.pass(ID, "dns.ipv6", "IPv6 address published", ""));
        } else {
            findings.add(Finding.warn(ID, "dns.ipv6.missing", LOW, "No IPv6 (AAAA) record",
                    "IPv6-only clients and some mobile networks reach the site through NAT64, adding latency.",
                    "Publish an AAAA record; most CDNs provide one automatically."));
        }
        return findings;
    }
}
