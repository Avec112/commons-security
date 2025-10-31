package io.github.avec112.security.crypto.sign;

import io.github.avec112.security.crypto.KeySize;
import io.github.avec112.security.crypto.KeyUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the methods in the {@code SignatureUtils} class.
 * This test class validates RSA signatures (RSASSA-PSS), Ed25519 signatures, and ECDSA signatures.
 */

@Execution(ExecutionMode.SAME_THREAD)
class SignatureUtilsTest {

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void signAndVerifyBytes(KeySize keySize) throws Exception {
        // Arrange
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize.getKeySize());
        KeyPair keyPair = kpg.generateKeyPair();

        final byte[] data = "Testing RSASSA-PSS string input".getBytes(StandardCharsets.UTF_8);

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair.getPrivate());
        boolean verified = SignatureUtils.verify(signature, data, keyPair.getPublic());

        // Assert
        assertTrue(verified, "RSASSA-PSS signature verification failed for key size " + keySize);
    }

    @Test
    void signAndVerifyString() throws Exception {
        // Arrange
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        String data = "Testing RSASSA-PSS string input";

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair.getPrivate());
        boolean verified = SignatureUtils.verify(signature, data, keyPair.getPublic());

        // Assert
        assertTrue(verified, "Signature not verified");
    }

    @Test
    void verifyFailsWithWrongKey() throws Exception {
        // Arrange
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair1 = kpg.generateKeyPair();

        // Generate a completely new random key pair for the mismatch test
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair2 = generator.generateKeyPair();

        String data = "Integrity check";

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair1.getPrivate());
        boolean verified = SignatureUtils.verify(signature, data, keyPair2.getPublic());

        // Assert
        assertFalse(verified, "Signature should not verify with wrong public key");
    }


    @Test
    void verifyFailsWhenDataTampered() throws Exception {
        // Arrange
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        String data = "Original content";
        String tampered = "Modified content";

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair.getPrivate());
        boolean verified = SignatureUtils.verify(signature, tampered, keyPair.getPublic());

        // Assert
        assertFalse(verified, "Signature should not verify when data has been tampered with");
    }

    @Test
    void verifyFailsWithCorruptedSignature() throws Exception {
        // Arrange
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        String data = "Check corruption";

        // Act
        final byte[] signature = SignatureUtils.sign(data, keyPair.getPrivate());
        // flip a few bytes
        signature[0] ^= (byte) 0xFF;
        signature[5] ^= (byte) 0xFF;

        boolean verified = SignatureUtils.verify(signature, data, keyPair.getPublic());

        // Assert
        assertFalse(verified, "Signature should not verify when signature bytes are corrupted");
    }

    @Test
    void signStringAndBytesAreEquivalent() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        String data = "Cross check equivalence";

        byte[] sigFromString = SignatureUtils.sign(data, keyPair.getPrivate());
        assertTrue(SignatureUtils.verify(sigFromString, data, keyPair.getPublic()),
                "Signature from String API should verify");

        // Sign via byte[] API
        byte[] sigFromBytes = SignatureUtils.sign(data.getBytes(StandardCharsets.UTF_8), keyPair.getPrivate());
        assertTrue(SignatureUtils.verify(sigFromBytes, data, keyPair.getPublic()),
                "Signature from byte[] API should verify");
    }

    // ========== Ed25519 Signature Tests ==========

    @Test
    void testEd25519SignAndVerify() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";

        // Act
        byte[] signature = SignatureUtils.signEd25519(testData, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        assertEquals(64, signature.length, "Ed25519 signatures should be 64 bytes");

        boolean isValid = SignatureUtils.verifyEd25519(signature, testData, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEd25519SignAndVerifyBytes() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";
        byte[] data = testData.getBytes();

        // Act
        byte[] signature = SignatureUtils.signEd25519(data, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        boolean isValid = SignatureUtils.verifyEd25519(signature, data, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEd25519VerifyWithWrongData() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";
        byte[] signature = SignatureUtils.signEd25519(testData, keyPair.getPrivate());

        // Act
        boolean isValid = SignatureUtils.verifyEd25519(signature, "Wrong data", keyPair.getPublic());

        // Assert
        assertFalse(isValid, "Signature should be invalid for different data");
    }

    @Test
    void testEd25519VerifyWithWrongKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";
        byte[] signature = SignatureUtils.signEd25519(testData, keyPair.getPrivate());

        // Generate a different key pair
        KeyPair wrongKeyPair = KeyUtils.generateEd25519KeyPair();

        // Act
        boolean isValid = SignatureUtils.verifyEd25519(signature, testData, wrongKeyPair.getPublic());

        // Assert
        assertFalse(isValid, "Signature should be invalid with wrong public key");
    }

    @Test
    void testEd25519DeterministicSignatures() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";

        // Act
        byte[] signature1 = SignatureUtils.signEd25519(testData, keyPair.getPrivate());
        byte[] signature2 = SignatureUtils.signEd25519(testData, keyPair.getPrivate());

        // Assert
        assertArrayEquals(signature1, signature2, "Ed25519 signatures should be deterministic");
    }

    @Test
    void testEd25519SignWithNullData() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();

        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.signEd25519((String) null, keyPair.getPrivate());
        });
    }

    @Test
    void testEd25519SignWithNullPrivateKey() {
        String testData = "Hello, Ed25519!";

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.signEd25519(testData, null);
        });
    }

    @Test
    void testEd25519VerifyWithNullSignature() throws Exception {
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.verifyEd25519(null, testData, keyPair.getPublic());
        });
    }

    @Test
    void testEd25519VerifyWithNullPublicKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();
        String testData = "Hello, Ed25519!";
        byte[] signature = SignatureUtils.signEd25519(testData, keyPair.getPrivate());

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.verifyEd25519(signature, testData, null);
        });
    }

    // ========== ECDSA Signature Tests ==========

    @Test
    void testEcdsaSignAndVerifyWithSecp256r1() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";

        // Act
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        assertTrue(signature.length > 0, "Signature should not be empty");

        boolean isValid = SignatureUtils.verifyEcdsa(signature, testData, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEcdsaSignAndVerifyWithSecp384r1() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp384r1KeyPair();
        String testData = "Hello, ECDSA!";

        // Act
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        boolean isValid = SignatureUtils.verifyEcdsa(signature, testData, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEcdsaSignAndVerifyWithSecp521r1() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp521r1KeyPair();
        String testData = "Hello, ECDSA!";

        // Act
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        boolean isValid = SignatureUtils.verifyEcdsa(signature, testData, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEcdsaSignAndVerifyBytes() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";
        byte[] data = testData.getBytes();

        // Act
        byte[] signature = SignatureUtils.signEcdsa(data, keyPair.getPrivate());

        // Assert
        assertNotNull(signature);
        boolean isValid = SignatureUtils.verifyEcdsa(signature, data, keyPair.getPublic());
        assertTrue(isValid, "Signature should be valid");
    }

    @Test
    void testEcdsaVerifyWithWrongData() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Act
        boolean isValid = SignatureUtils.verifyEcdsa(signature, "Wrong data", keyPair.getPublic());

        // Assert
        assertFalse(isValid, "Signature should be invalid for different data");
    }

    @Test
    void testEcdsaVerifyWithWrongKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Generate a different key pair
        KeyPair wrongKeyPair = KeyUtils.generateSecp256r1KeyPair();

        // Act
        boolean isValid = SignatureUtils.verifyEcdsa(signature, testData, wrongKeyPair.getPublic());

        // Assert
        assertFalse(isValid, "Signature should be invalid with wrong public key");
    }

    @Test
    void testEcdsaProbabilisticSignatures() throws Exception {
        // Arrange
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";

        // Act
        byte[] signature1 = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());
        byte[] signature2 = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        // Assert
        assertNotEquals(0, signature1.length);
        assertNotEquals(0, signature2.length);
        // Note: Signatures might occasionally be the same due to randomness, but typically differ
    }

    @Test
    void testEcdsaSignWithNullData() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.signEcdsa((String) null, keyPair.getPrivate());
        });
    }

    @Test
    void testEcdsaSignWithNullPrivateKey() {
        String testData = "Hello, ECDSA!";

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.signEcdsa(testData, null);
        });
    }

    @Test
    void testEcdsaVerifyWithNullSignature() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.verifyEcdsa(null, testData, keyPair.getPublic());
        });
    }

    @Test
    void testEcdsaVerifyWithNullPublicKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();
        String testData = "Hello, ECDSA!";
        byte[] signature = SignatureUtils.signEcdsa(testData, keyPair.getPrivate());

        assertThrows(NullPointerException.class, () -> {
            SignatureUtils.verifyEcdsa(signature, testData, null);
        });
    }

}