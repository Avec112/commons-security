package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.ecc.EccCurve;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the methods in the {@code KeyUtils} class.
 * This test class validates the generation and integrity of RSA key pairs using different key sizes.
 * Additionally, it ensures that generated key pairs meet expected criteria.
 */
@Execution(ExecutionMode.CONCURRENT)
class KeyUtilsTest extends BouncyCastleProviderInitializer {

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void generateKeyPair(KeySize keySize) throws Exception {
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(keySize);
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, keySize.getKeySize());
    }

    @Test
    void generateDefaultRsaKeyPair() throws Exception {

        // Arrange
        KeySize defaultKeySize = KeySize.BIT_3072;

        // Act
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair();

        // Assert
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, defaultKeySize.getKeySize());
    }

    @Test
    void generateRsaKeyPair4096() throws Exception {
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair4096();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_4096.getKeySize());
    }

    @Test
    void generateRsaKeyPair3072() throws Exception {
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair3072();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_3072.getKeySize());
    }

    @Test
    void generateRsaKeyPair2048() throws Exception {
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair2048();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_2048.getKeySize());
    }

    private static void assertKeyPairNotNull(KeyPair keyPair) {
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    private static void assertKeyPairBitLengthEquals(KeyPair keyPair, int bitLength) {
        int publicBits = ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength();
        int privateBits = ((RSAPrivateKey) keyPair.getPrivate()).getModulus().bitLength();
        assertEquals(bitLength, publicBits);
        assertEquals(bitLength, privateBits);
    }

    // ========== ECC Key Generation Tests ==========

    @Test
    void testGenerateEd25519KeyPair() throws Exception {
        KeyPair keyPair = KeyUtils.generateEd25519KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("Ed25519", keyPair.getPublic().getAlgorithm());
        assertEquals("Ed25519", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp256r1KeyPair() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp384r1KeyPair() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp384r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp521r1KeyPair() throws Exception {
        KeyPair keyPair = KeyUtils.generateSecp521r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairWithDefaultCurve() throws Exception {
        KeyPair keyPair = KeyUtils.generateEcKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairWithSpecificCurve() throws Exception {
        KeyPair keyPair = KeyUtils.generateEcKeyPair(EccCurve.SECP384R1);

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairThrowsExceptionForEd25519() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            KeyUtils.generateEcKeyPair(EccCurve.ED25519);
        });

        assertTrue(exception.getMessage().contains("Ed25519"));
    }
}