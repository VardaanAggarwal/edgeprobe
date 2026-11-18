package dev.vardaan.edgeprobe.core.net;

import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/** Turns low-level exceptions into short messages fit for a report. */
final class Errors {

    private Errors() {
    }

    static Throwable unwrap(Throwable t) {
        Throwable current = t;
        while ((current instanceof CompletionException || current instanceof ExecutionException
                || current instanceof UncheckedIOException) && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    static String describe(Throwable t) {
        Throwable e = unwrap(t);
        if (e instanceof HttpConnectTimeoutException) {
            return "connection timed out";
        }
        if (e instanceof HttpTimeoutException || e instanceof SocketTimeoutException) {
            return "timed out waiting for a response";
        }
        if (e instanceof ConnectException) {
            return "connection refused";
        }
        if (e instanceof UnknownHostException) {
            return "host does not resolve";
        }
        if (e instanceof TargetException) {
            return e.getMessage();
        }
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof CertificateExpiredException) {
                return "certificate has expired";
            }
            if (c instanceof CertificateNotYetValidException) {
                return "certificate is not yet valid";
            }
            String message = c.getMessage() == null ? "" : c.getMessage();
            if (message.contains("No subject alternative") || message.contains("No name matching")) {
                return "certificate does not cover this host name";
            }
            if (message.contains("unable to find valid certification path")) {
                return "certificate chain does not lead to a trusted root (self-signed, or an intermediate is missing)";
            }
        }
        String message = e.getMessage();
        return e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }
}
