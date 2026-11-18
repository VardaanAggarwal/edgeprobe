package dev.vardaan.edgeprobe.core.net;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * What the TLS handshake revealed.
 *
 * @param trusted        whether the chain validated against the trust store and matched the host name
 * @param handshakeError the validation error when {@code trusted} is false
 * @param protocol       negotiated protocol, such as "TLSv1.3"
 * @param cipherSuite    negotiated cipher suite
 * @param chain          certificates as sent by the server, leaf first
 */
public record TlsInfo(boolean trusted, String handshakeError, String protocol, String cipherSuite,
                      List<CertInfo> chain) {

    public TlsInfo {
        chain = chain == null ? List.of() : List.copyOf(chain);
    }

    public Optional<CertInfo> leaf() {
        return chain.isEmpty() ? Optional.empty() : Optional.of(chain.get(0));
    }

    /**
     * @param keyAlgorithm "RSA" or "EC"
     * @param keyBits      RSA modulus length or EC field size
     */
    public record CertInfo(String subject, String issuer, Instant notBefore, Instant notAfter,
                           List<String> subjectAltNames, String signatureAlgorithm,
                           String keyAlgorithm, int keyBits) {

        public CertInfo {
            subjectAltNames = List.copyOf(subjectAltNames);
        }

        public boolean selfSigned() {
            return subject.equals(issuer);
        }
    }
}
