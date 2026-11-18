package dev.vardaan.edgeprobe.core.check;

import static dev.vardaan.edgeprobe.core.model.Severity.MEDIUM;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Text responses should be compressed. The prober advertises br, gzip and zstd. */
public final class CompressionCheck implements Check {

    static final String ID = "compression";
    private static final Set<String> ENCODINGS = Set.of("br", "gzip", "zstd", "deflate");
    private static final List<String> TEXT_TYPES = List.of(
            "text/", "application/json", "application/javascript", "application/xml", "image/svg+xml");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String description() {
        return "Text responses use br, gzip or zstd compression";
    }

    @Override
    public List<Finding> evaluate(SiteSnapshot s) {
        Optional<List<Finding>> blocked = PageGuard.unusable(s, ID);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        HttpExchange r = s.finalHttps().orElseThrow();
        String type = r.header("content-type").orElse("").toLowerCase(Locale.ROOT);
        if (TEXT_TYPES.stream().noneMatch(type::startsWith)) {
            return List.of(Finding.info(ID, "compression.not-applicable", "Not a text response",
                    type.isEmpty() ? "No Content-Type" : type));
        }
        String encoding = r.header("content-encoding").orElse("").strip().toLowerCase(Locale.ROOT);
        if (ENCODINGS.contains(encoding)) {
            return List.of(Finding.pass(ID, "compression", "Compressed with " + encoding, type));
        }
        return List.of(Finding.warn(ID, "compression.missing", MEDIUM, "Text response is not compressed",
                type + " was sent uncompressed although the client accepts br, gzip and zstd.",
                "Enable Brotli or gzip for text content at the origin or the CDN."));
    }
}
