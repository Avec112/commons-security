package com.github.avec112.security.crypto.aes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AesUtilsTest {

    // Reuse one SecureRandom instance across tests
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    void getRandomNonce_returnsExpectedLengthAndIsRandom() {
        // Arrange
        int length = 12;

        // Act
        byte[] nonce1 = AesUtils.getRandomNonce(length);
        byte[] nonce2 = AesUtils.getRandomNonce(length);

        // Assert
        assertNotNull(nonce1);
        assertEquals(length, nonce1.length);
        assertFalse(java.util.Arrays.equals(nonce1, nonce2),
                "Nonces should be different on each call");
    }

    @ParameterizedTest
    @EnumSource(EncryptionStrength.class)
    void generateBase64Key_hasCorrectDecodedLength(EncryptionStrength strength) {
        // Arrange
        int expectedBytes = strength.getLength() / 8;

        // Act
        String key = AesUtils.generateBase64Key(strength);
        byte[] decoded = Base64.getDecoder().decode(key);

        // Assert
        assertNotNull(key);
        assertNotNull(key, "Key must not be null");
        assertFalse(key.trim().isEmpty(), "Key should not be blank");
        assertEquals(expectedBytes, decoded.length,
                "Decoded key length must match AES strength");
    }

    @Test
    void getAESKey_returnsKeyWithCorrectLength() throws Exception {
        // Arrange
        int key128 = 128;
        int key256 = 256;

        // Act
        SecretKey secret128 = AesUtils.getAESKey(key128);
        SecretKey secret256 = AesUtils.getAESKey(key256);

        // Assert
        assertEquals(16, secret128.getEncoded().length);
        assertEquals(32, secret256.getEncoded().length);
    }

    @Test
    void getAESKeyFromPassword_derivesDeterministicKey() throws Exception {
        // Arrange
        char[] password = "StrongPassword!".toCharArray();
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        // Act
        SecretKey key1 = AesUtils.getAESKeyFromPassword(password, salt, 256);
        SecretKey key2 = AesUtils.getAESKeyFromPassword(password, salt, 256);

        // Assert
        assertArrayEquals(key1.getEncoded(), key2.getEncoded(),
                "PBKDF2 should produce deterministic keys for same password+salt");
    }

    @Test
    void getAESKeyFromPassword_differentSaltProducesDifferentKey() throws Exception {
        // Arrange
        char[] password = "StrongPassword!".toCharArray();
        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        SECURE_RANDOM.nextBytes(salt1);
        SECURE_RANDOM.nextBytes(salt2);

        // Act
        SecretKey key1 = AesUtils.getAESKeyFromPassword(password, salt1, 256);
        SecretKey key2 = AesUtils.getAESKeyFromPassword(password, salt2, 256);

        // Assert
        assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different salts should produce different keys");
    }
}