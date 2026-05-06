package io.github.avec112.security;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Utility class to provide the version information of the application.
 *
 * The version is retrieved from the Maven-generated `pom.properties` file located
 * in the classpath under the directory `META-INF/maven` of the specified artifact.
 */
public final class VersionProvider {
    private static final String POM_PROPERTIES =
            "META-INF/maven/io.github.avec112/commons-security-core/pom.properties";

    private VersionProvider() {}

    public static String getVersion() {
        return loadVersion(VersionProvider.class.getClassLoader().getResourceAsStream(POM_PROPERTIES));
    }

    static String loadVersion(InputStream inputStream) {
        if (inputStream == null) {
            return "unknown";
        }

        try (inputStream) {
            Properties properties = new Properties();
            properties.load(inputStream);
            return properties.getProperty("version", "unknown");
        } catch (IOException e) {
            return "unknown";
        }
    }
}
