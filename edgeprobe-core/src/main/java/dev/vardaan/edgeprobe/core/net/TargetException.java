package dev.vardaan.edgeprobe.core.net;

/** Base type for "we will not or cannot scan this target". Callers map subclasses to 4xx responses. */
public abstract sealed class TargetException extends RuntimeException
        permits InvalidTargetException, BlockedTargetException, UnresolvableHostException {

    protected TargetException(String message) {
        super(message);
    }
}
