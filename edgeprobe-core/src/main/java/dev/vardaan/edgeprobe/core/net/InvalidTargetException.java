package dev.vardaan.edgeprobe.core.net;

/** The input is not a scannable http(s) URL. */
public final class InvalidTargetException extends TargetException {

    public InvalidTargetException(String message) {
        super(message);
    }
}
