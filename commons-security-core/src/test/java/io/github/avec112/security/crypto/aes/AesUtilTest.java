package io.github.avec112.security.crypto.aes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AesUtilTest {

    // Reuse one SecureRandom instance across tests
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    void getRandomNonce_returnsExpectedLengthAndIsRandom() {
        // Arrange
        int length = 12;

        // Act
        byte[] nonce1 = AesUtil.getRandomNonce(length);
        byte[] nonce2 = AesUtil.getRandomNonce(length);

        // Assert
        assertNotNull(nonce1);
        assertEquals(length, nonce1.length);
        assertFalse(java.util.Arrays.equals(nonce1, nonce2),
                "Nonces should be different on each call");
    }

    /**
     * 1 byte Secure Random Nonce has 129 possible results.
     * With 10000 tries we should hit every 129 by a good margin.
     * This test validates that SecureRandom properly distributes values.
     */
    @ParameterizedTest
    @ValueSource(ints = 10000)
    void getRandomNonce_producesFullRangeOfByteValues(int iterations) {
        // Arrange
        Set<String> uniqueValues = new HashSet<>();

        // Act
        for (int i = 0; i < iterations; i++) {
            byte[] nonce = AesUtil.getRandomNonce(1);
            uniqueValues.add(new String(nonce));
        }

        // Assert
        assertEquals(129, uniqueValues.size(),
                "1-byte nonce should produce all 129 possible byte values over " + iterations + " iterations");
    }

    @ParameterizedTest
    @EnumSource(AesKeySize.class)
    void generateBase64Key_hasCorrectDecodedLength(AesKeySize aesKeySize) {
        // Arrange
        int expectedBytes = aesKeySize.getKeySize() / 8;

        // Act
        String key = AesUtil.generateBase64Key(aesKeySize);
        byte[] decoded = Base64.getDecoder().decode(key);

        // Assert
        assertNotNull(key);
        assertNotNull(key, "Key must not be null");
        assertFalse(key.trim().isEmpty(), "Key should not be blank");
        assertEquals(expectedBytes, decoded.length,
                "Decoded key length must match AES keySize");
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void getAESKey_returnsKeyWithCorrectLength(int keySize) throws Exception {
        // Arrange
        int expectedBytes = keySize / 8;

        // Act
        SecretKey secretKey = AesUtil.getAESKey(keySize);

        // Assert
        assertEquals(expectedBytes, secretKey.getEncoded().length,
                "AES-" + keySize + " key should be " + expectedBytes + " bytes");
    }

    @Test
    void getAESKeyFromPassword_derivesDeterministicKey() throws Exception {
        // Arrange
        char[] password = "StrongPassword!".toCharArray();
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        // Act
        SecretKey key1 = AesUtil.getAESKeyFromPassword(password, salt, 256);
        SecretKey key2 = AesUtil.getAESKeyFromPassword(password, salt, 256);

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
        SecretKey key1 = AesUtil.getAESKeyFromPassword(password, salt1, 256);
        SecretKey key2 = AesUtil.getAESKeyFromPassword(password, salt2, 256);

        // Assert
        assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different salts should produce different keys");
    }
}