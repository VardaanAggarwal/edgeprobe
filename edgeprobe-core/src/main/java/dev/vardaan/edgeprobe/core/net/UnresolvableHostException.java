package dev.vardaan.edgeprobe.core.net;

/** DNS returned no address for the host. */
public final class UnresolvableHostException extends TargetException {

    public UnresolvableHostException(String message) {
        super(message);
    }
}
