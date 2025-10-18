package io.github.avec112.security.crypto.sign;

import io.github.avec112.security.crypto.rsa.KeySize;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for SignatureUtils using RSASSA-PSS (SHA-256 with MGF1).
 * Ensures correct signing, verification, and failure conditions.
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

}