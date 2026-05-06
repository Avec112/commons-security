package io.github.avec112.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.InputStream;
import java.util.Properties;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;

class VersionProviderIT {

    @Test
    void packagedJar_shouldContainPomPropertiesWithProjectVersion() throws Exception {
        String projectVersion = System.getProperty("projectVersion");
        String finalName = System.getProperty("projectBuildFinalName");

        File jarFile = new File("target/" + finalName + ".jar");

        assertThat(jarFile).as("Packaged JAR should exist").exists();

        try (JarFile jar = new JarFile(jarFile)) {
            var entry = jar.getEntry("META-INF/maven/io.github.avec112/commons-security-core/pom.properties");

            assertThat(entry)
                    .as("pom.properties should exist inside the packaged JAR")
                    .isNotNull();

            Properties properties = new Properties();

            try (InputStream inputStream = jar.getInputStream(entry)) {
                properties.load(inputStream);
            }

            assertThat(properties.getProperty("version"))
                    .as("pom.properties version should match Maven project version")
                    .isEqualTo(projectVersion);
        }
    }
}
