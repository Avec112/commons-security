package io.github.avec112.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class VersionProviderTest {

    @Test
    void getVersion_shouldReturnNonBlankValue() {
        assertThat(VersionProvider.getVersion()).isNotBlank();
    }

    @Test
    void loadVersion_shouldHandleMissingResource() {
        assertThat(VersionProvider.loadVersion(null)).isEqualTo("unknown");
    }
}
