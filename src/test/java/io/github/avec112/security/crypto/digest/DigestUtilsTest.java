package io.github.avec112.security.crypto.digest;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DigestUtilsTest extends BouncyCastleProviderInitializer {



    @ParameterizedTest
    @CsvSource({
            "Hello!",
            "æøåö",
            "1234!#&"
    })
    void digest(String data) throws Exception {
        // Arrange
        final byte[] expected = MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8));

        // Act
        final byte[] actual = DigestUtils.digest(data);

        // Assert
        assertArrayEquals(expected, actual);
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, M00Bb3Vc1txYxTqG4YOIL47BT1L7BTRYh8il7dQsh7c=",
            "æøåö, UPidDtYmr13NOL12KJr2RLpkBZoLbHEjqiEVkFJ86bw=",
            "1234!#&, RmLkQ2aE6W0lH9ByrQFb1n0fzyBYuTPyZReDqwr2oaE="
    })
    void base64Digest(String data, String expected) throws Exception {
        final String actual = DigestUtils.base64Digest(data);
        assertEquals(expected, actual);
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, 334d016f755cd6dc58c53a86e183882f8ec14f52fb05345887c8a5edd42c87b7",
            "æøåö, 50f89d0ed626af5dcd38bd76289af644ba64059a0b6c7123aa211590527ce9bc",
            "1234!#&, 4662e4436684e96d251fd072ad015bd67d1fcf2058b933f2651783ab0af6a1a1"
    })
    void hexDigest(String data, String expected) throws Exception {
        final String actual = DigestUtils.hexDigest(data);
        assertEquals(expected, actual);
    }

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void digestWithAlgorithm(DigestAlgorithm digestAlgorithm) throws Exception {
        final String data = "test data";
        final byte[] actual = DigestUtils.digest(data, digestAlgorithm);
        final byte[] expected = MessageDigest.getInstance(digestAlgorithm.getAlgorithm()).digest(data.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected, actual);
    }

    /**
     * Verifies the SHA-256 digest against a known fixed test vector ("OpenAI").
     * Ensures the implementation produces the exact expected hash value.
     */
    @Test
    void knownFixedDigestVector_sha256_OpenAI() throws Exception {
        // Arrange
        final String data = "OpenAI";
        final String expectedHex = "8b7d1a3187ab355dc31bc683aaa71ab5ed217940c12196a9cd5f4ca984babfa4";

        // Act
        final String actualHex = DigestUtils.hexDigest(data);

        // Assert
        assertEquals(expectedHex, actualHex);
    }

}