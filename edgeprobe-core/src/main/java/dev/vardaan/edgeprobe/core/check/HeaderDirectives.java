package dev.vardaan.edgeprobe.core.check;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Parses comma- or semicolon-separated directive headers such as
 * {@code Cache-Control: public, max-age=600} or {@code Strict-Transport-Security: max-age=31536000; includeSubDomains}.
 * Directive names are lower-cased; quoted values are unquoted.
 */
final class HeaderDirectives {

    private final Map<String, String> directives;

    private HeaderDirectives(Map<String, String> directives) {
        this.directives = directives;
    }

    static HeaderDirectives parse(String header, char separator) {
        Map<String, String> map = new LinkedHashMap<>();
        if (header != null) {
            for (String part : header.split(java.util.regex.Pattern.quote(String.valueOf(separator)))) {
                String token = part.strip();
                if (token.isEmpty()) {
                    continue;
                }
                int eq = token.indexOf('=');
                String name = (eq < 0 ? token : token.substring(0, eq)).strip().toLowerCase(Locale.ROOT);
                String value = eq < 0 ? "" : token.substring(eq + 1).strip();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                map.putIfAbsent(name, value);
            }
        }
        return new HeaderDirectives(map);
    }

    boolean has(String name) {
        return directives.containsKey(name);
    }

    Optional<Long> seconds(String name) {
        String value = directives.get(name);
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
