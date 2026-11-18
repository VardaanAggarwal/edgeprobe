package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.CRITICAL;
import static dev.vardaan.edgeprobe.core.model.Severity.HIGH;
import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import dev.vardaan.edgeprobe.core.net.TlsInfo;
import dev.vardaan.edgeprobe.core.net.TlsInfo.CertInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Certificate trust and expiry, protocol version, key strength and signature algorithm. */
public final class TlsCheck implements Check {

    static final String ID = "tls";
    /** ACME clients such as certbot renew at 30 days left, so under 21 usually means renewal is broken. */
    static final int WARN_DAYS = 21;
    static final int FAIL_DAYS = 7;

    private final Clock clock;

    public TlsCheck(Clock clock) {
        this.clock = clock;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "Certificate trust, hostname match and expiry; TLS version; key size; signature algorithm";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot snapshot) {
        Optional<TlsInfo> maybeTls = snapshot.tlsInfo();
        if (maybeTls.isEmpty()) {
            return List.of(Finding.fail(ID, "tls.unavailable", CRITICAL, "HTTPS is not available",
                    "TLS handshake on port 443 failed: " + snapshot.error("tls").orElse("unknown error"),
                    "Serve the site over HTTPS with a certificate from a public CA (for example Let's Encrypt)."));
        }
        TlsInfo tls = maybeTls.get();
        List<Finding> findings = new ArrayList<>();

        if (!tls.trusted()) {
            String leafDetail = tls.leaf().map(c -> " Leaf: " + c.subject() + ", issued by " + c.issuer()
                    + (c.selfSigned() ? " (self-signed)" : "") + ".").orElse("");
            findings.add(Finding.fail(ID, "tls.untrusted", CRITICAL, "Certificate is not trusted",
                    capitalize(tls.handshakeError()) + "." + leafDetail,
                    "Install a certificate from a public CA that covers this host name, and serve the full "
                            + "chain including intermediates."));
        } else {
            findings.add(Finding.pass(ID, "tls.trusted", "Certificate is trusted",
                    tls.leaf().map(c -> "Issued by " + c.issuer()).orElse("")));
        }

        findings.add(protocolFinding(tls.protocol()));
        tls.leaf().ifPresent(leaf -> {
            findings.add(expiryFinding(leaf));
            findings.add(keyFinding(leaf));
            findings.add(signatureFinding(leaf));
        });
        return findings;
    }

    private Finding protocolFinding(String protocol) {
        if (protocol == null) {
            return Finding.error(ID, "Negotiated protocol unknown");
        }
        return switch (protocol) {
            case "TLSv1.3" -> Finding.pass(ID, "tls.protocol", "TLS 1.3 negotiated", "");
            case "TLSv1.2" -> Finding.pass(ID, "tls.protocol", "TLS 1.2 negotiated",
                    "TLS 1.3 is preferred: one fewer round trip per new connection.");
            default -> Finding.fail(ID, "tls.protocol.legacy", HIGH, "Legacy TLS version " + protocol,
                    "The best protocol the server offered was " + protocol + ", which browsers no longer accept.",
                    "Enable TLS 1.2 and 1.3; disable TLS 1.0 and 1.1.");
        };
    }

    private Finding expiryFinding(CertInfo leaf) {
        Instant now = clock.instant();
        long days = Duration.between(now, leaf.notAfter()).toDays();
        String when = "expires " + leaf.notAfter();
        if (now.isBefore(leaf.notBefore())) {
            return Finding.fail(ID, "tls.cert.not-yet-valid", CRITICAL, "Certificate is not valid yet",
                    "Valid from " + leaf.notBefore(), "Check the server clock and the certificate's issue date.");
        }
        if (now.isAfter(leaf.notAfter())) {
            return Finding.fail(ID, "tls.cert.expired", CRITICAL, "Certificate has expired",
                    "Expired " + leaf.notAfter(), "Renew the certificate now and automate renewal.");
        }
        if (days < FAIL_DAYS) {
            return Finding.fail(ID, "tls.cert.expiring", HIGH, "Certificate expires in " + days + " days", when,
                    "Renew now. Automated renewal appears to be failing.");
        }
        if (days < WARN_DAYS) {
            return Finding.warn(ID, "tls.cert.expiring", MEDIUM, "Certificate expires in " + days + " days", when,
                    "Automated renewal normally runs at 30 days left; check that it is working.");
        }
        return Finding.pass(ID, "tls.cert.validity", "Certificate valid for " + days + " more days", when);
    }

    private Finding keyFinding(CertInfo leaf) {
        String algorithm = leaf.keyAlgorithm().toUpperCase(Locale.ROOT);
        boolean weak = (algorithm.equals("RSA") && leaf.keyBits() < 2048)
                || (algorithm.equals("EC") && leaf.keyBits() < 256);
        String described = leaf.keyAlgorithm() + " " + leaf.keyBits() + "-bit key";
        if (weak) {
            return Finding.fail(ID, "tls.key.weak", HIGH, "Weak " + described, "",
                    "Reissue with an RSA 2048+ or ECDSA P-256 key.");
        }
        return Finding.pass(ID, "tls.key", described, "");
    }

    private Finding signatureFinding(CertInfo leaf) {
        String sig = leaf.signatureAlgorithm().toUpperCase(Locale.ROOT);
        if (sig.contains("SHA1") || sig.contains("MD5")) {
            return Finding.fail(ID, "tls.signature.weak", HIGH, "Weak signature algorithm " + leaf.signatureAlgorithm(),
                    "", "Reissue the certificate with a SHA-256 based signature.");
        }
        return Finding.pass(ID, "tls.signature", "Signed with " + leaf.signatureAlgorithm(), "");
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) {
            return "Validation failed";
        }
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
