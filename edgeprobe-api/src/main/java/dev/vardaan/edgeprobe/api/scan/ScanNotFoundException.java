package dev.vardaan.edgeprobe.api.scan;

import java.util.UUID;

public class ScanNotFoundException extends RuntimeException {

    public ScanNotFoundException(UUID id) {
        super("No scan with id " + id);
    }
}
