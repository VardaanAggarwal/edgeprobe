package dev.vardaan.edgeprobe.core.net;

/** The target resolves to an address the {@link AddressPolicy} forbids, such as a private network. */
public final class BlockedTargetException extends TargetException {

    public BlockedTargetException(String message) {
        super(message);
    }
}
