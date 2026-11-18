package dev.vardaan.edgeprobe.core.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class TargetUrlTest {

    @ParameterizedTest
    @CsvSource({
            "example.com,                       https://example.com/",
            "https://Example.COM,                https://example.com/",
            "http://example.com/a/b?q=1#frag,    https://example.com/a/b?q=1",
            "https://example.com.:443/x,         https://example.com/x",
            "'  example.com/path  ',             https://example.com/path",
            "https://[2606:4700::1111]/,         https://[2606:4700::1111]/"
    })
    void normalizes(String input, String expected) {
        assertThat(TargetUrl.parse(input).canonical()).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "ftp://example.com", "file:///etc/passwd", "https://user:pw@example.com",
            "https://example.com:8080/", "https://exa mple.com", "https://-bad-.com", "javascript:alert(1)"})
    void rejects(String input) {
        assertThatThrownBy(() -> TargetUrl.parse(input)).isInstanceOf(InvalidTargetException.class);
    }

    @Test
    void buildsPerSchemeUrisWithNonDefaultPortsOnlyWhenNeeded() {
        TargetUrl target = TargetUrl.parse("example.com/a?b=c");
        assertThat(target.uri("http", 80)).hasToString("http://example.com/a?b=c");
        assertThat(target.uri("https", 8443)).hasToString("https://example.com:8443/a?b=c");
    }

    @Test
    void ipv6HostIsStoredWithoutBrackets() {
        assertThat(TargetUrl.parse("https://[::1]/").host()).isEqualTo("::1");
    }
}
