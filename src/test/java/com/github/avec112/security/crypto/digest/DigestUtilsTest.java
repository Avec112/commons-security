package com.github.avec112.security.crypto.digest;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

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
        final byte[] expected = MessageDigest.getInstance("SHA-256", "BC").digest(data.getBytes());

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
            "Hello!, M00Bb3Vc1txYxTqG4YOIL47BT1L7BTRYh8il7dQsh7c=",
            "æøåö, UPidDtYmr13NOL12KJr2RLpkBZoLbHEjqiEVkFJ86bw=",
            "1234!#&, RmLkQ2aE6W0lH9ByrQFb1n0fzyBYuTPyZReDqwr2oaE="
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
//        System.out.println(digestAlgorithm.getAlgorithm() + ": " + EncodingUtils.hexEncode(actual));
        final byte[] expected = MessageDigest.getInstance(digestAlgorithm.getAlgorithm()).digest(data.getBytes());
        assertArrayEquals(expected, actual);
    }
}