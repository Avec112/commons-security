package com.github.avec112.security.crypto.digest;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;
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
        final byte[] expected = MessageDigest.getInstance("SHA-512/256").digest(data.getBytes(StandardCharsets.UTF_8));

        // Act
        final byte[] actual = DigestUtils.digest(data);

        // Assert
        assertArrayEquals(expected, actual);
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, wntqA71ep8/rMKDKhsgUT68U/8Kbfm3v6Um8seOypUo=",
            "æøåö, Y8MszG0XyMjkj+0SNqKyZ/R9sSOYjyFbRsOkVT2WonY=",
            "1234!#&, 7tFYVk6O4ihJ4xSoT7b1owFEy+9ObozhGQKrIWI1EKo="
    })
    void base64Digest(String data, String expected) throws Exception {
        final String actual = DigestUtils.base64Digest(data);
        assertEquals(expected, actual);
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, c27b6a03bd5ea7cfeb30a0ca86c8144faf14ffc29b7e6defe949bcb1e3b2a54a",
            "æøåö, 63c32ccc6d17c8c8e48fed1236a2b267f47db123988f215b46c3a4553d96a276",
            "1234!#&, eed158564e8ee22849e314a84fb6f5a30144cbef4e6e8ce11902ab21623510aa"
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
        final String expectedHex = "88d4629ddbe9e0f14fe203e5a1cfa06a00793c20ea32a734d406452d29b6f838";

        // Act
        final String actualHex = DigestUtils.hexDigest(data);

        // Assert
        assertEquals(expectedHex, actualHex);
    }

}