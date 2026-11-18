package dev.vardaan.edgeprobe.core.check;

import dev.vardaan.edgeprobe.core.model.Finding;
import dev.vardaan.edgeprobe.core.net.HttpExchange;
import dev.vardaan.edgeprobe.core.net.SiteSnapshot;
import java.util.List;
import java.util.Optional;

/**
 * Header checks must only judge the site's real page. If the final HTTPS response is missing or
 * not 2xx (bot protection answering 403, a 503 maintenance page), its headers describe the block
 * page, not the site, and judging them would produce false failures. Such checks report ERROR
 * ("could not verify") instead.
 */
final class PageGuard {

    private PageGuard() {
    }

    /** The final 2xx HTTPS page, or the ERROR findings to return instead. */
    static Optional<List<Finding>> unusable(SiteSnapshot s, String checkId) {
        Optional<HttpExchange> response = s.finalHttps();
        if (response.isEmpty()) {
            return Optional.of(List.of(Finding.error(checkId, "No final HTTPS response to inspect"
                    + s.error("https").map(e -> ": " + e).orElse(""))));
        }
        int status = response.get().status();
        if (status < 200 || status >= 300) {
            return Optional.of(List.of(Finding.error(checkId, "The final HTTPS response was " + status
                    + ", which is usually bot protection or an error page, so its headers were not evaluated")));
        }
        return Optional.empty();
    }
}
