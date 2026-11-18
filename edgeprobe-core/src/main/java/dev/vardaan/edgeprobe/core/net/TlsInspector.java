package dev.vardaan.edgeprobe.core.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Performs a TLS handshake and records the protocol, cipher and certificate chain.
 *
 * <p>It connects to an address that {@link HostResolver} already approved, rather than letting
 * the socket resolve the name again, and sends the host name through SNI.
 *
 * <p>If validation fails, it handshakes a second time with a trust-everything context, only to
 * read the certificates and explain the failure ("expired on 3 March", "self-signed"). Nothing
 * is ever sent over that second connection.
 */
final class TlsInspector {

    private final ProberConfig config;

    TlsInspector(ProberConfig config) {
        this.config = config;
    }

    TlsInfo inspect(String host, InetAddress address, int port) throws IOException {
        try {
            return handshake(host, address, port, config.sslContext(), true);
        } catch (SSLException validationFailure) {
            String reason = Errors.describe(validationFailure);
            try {
                TlsInfo untrusted = handshake(host, address, port, trustAllContext(), false);
                return new TlsInfo(false, reason, untrusted.protocol(), untrusted.cipherSuite(), untrusted.chain());
            } catch (IOException e) {
                return new TlsInfo(false, reason, null, null, List.of());
            }
        }
    }

    private TlsInfo handshake(String host, InetAddress address, int port, SSLContext context,
                              boolean verify) throws IOException {
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(address, port), (int) config.connectTimeout().toMillis());
            raw.setSoTimeout((int) config.requestTimeout().toMillis());
            try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(raw, host, port, true)) {
                SSLParameters params = socket.getSSLParameters();
                if (verify) {
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                }
                if (!host.contains(":") && !Character.isDigit(host.charAt(host.length() - 1))) {
                    params.setServerNames(List.of(new SNIHostName(host)));
                }
                socket.setSSLParameters(params);
                socket.startHandshake();
                SSLSession session = socket.getSession();
                List<TlsInfo.CertInfo> chain = new ArrayList<>();
                for (Certificate cert : session.getPeerCertificates()) {
                    if (cert instanceof X509Certificate x509) {
                        chain.add(describe(x509));
                    }
                }
                return new TlsInfo(verify, null, session.getProtocol(), session.getCipherSuite(), chain);
            }
        }
    }

    static TlsInfo.CertInfo describe(X509Certificate cert) {
        List<String> sans = new ArrayList<>();
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> entry : altNames) {
                    int type = (Integer) entry.get(0);
                    if (type == 2 || type == 7) {
                        sans.add(String.valueOf(entry.get(1)));
                    }
                }
            }
        } catch (CertificateParsingException ignored) {
            // A certificate with a malformed SAN extension is reported with no SANs.
        }
        PublicKey key = cert.getPublicKey();
        int bits = 0;
        if (key instanceof RSAPublicKey rsa) {
            bits = rsa.getModulus().bitLength();
        } else if (key instanceof ECPublicKey ec) {
            bits = ec.getParams().getCurve().getField().getFieldSize();
        }
        return new TlsInfo.CertInfo(
                cert.getSubjectX500Principal().getName(X500Principal.RFC2253),
                cert.getIssuerX500Principal().getName(X500Principal.RFC2253),
                cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(),
                sans,
                cert.getSigAlgName(),
                key.getAlgorithm(),
                bits);
    }

    private static SSLContext trustAllContext() throws IOException {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new InspectOnlyTrustManager()}, null);
            return context;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("Could not build inspection TLS context", e);
        }
    }

    /** Accepts any chain. Used only to read certificates after a validation failure. */
    private static final class InspectOnlyTrustManager extends X509ExtendedTrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
