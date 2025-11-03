package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.aes.AesKeySize;
import io.github.avec112.security.crypto.ecc.EccCurve;
import io.github.avec112.security.crypto.rsa.RsaKeySize;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the methods in the {@code KeyGeneratorUtils} class.
 * This test class validates the generation and integrity of RSA key pairs using different key sizes.
 * Additionally, it ensures that generated key pairs meet expected criteria.
 */
@Execution(ExecutionMode.CONCURRENT)
class KeyGeneratorUtilsTest extends BouncyCastleProviderInitializer {


    @ParameterizedTest
    @EnumSource(AesKeySize.class)
    void generateAesKey(AesKeySize keySize) throws Exception {
        int expectedKeySizeInBytes = keySize.getKeySize()/8;
        final SecretKey secretKey = KeyGeneratorUtils.generateAesKey(keySize);
        assertNotNull(secretKey);
        assertEquals(expectedKeySizeInBytes, secretKey.getEncoded().length);
    }

    @Test
    void generateDefaultAesKey() throws Exception {
        int expectedKeySizeInBytes = AesKeySize.BIT_256.getKeySize()/8;

        final SecretKey secretKey = KeyGeneratorUtils.generateAesKey();

        assertNotNull(secretKey);
        assertEquals(expectedKeySizeInBytes, secretKey.getEncoded().length);
    }


    @ParameterizedTest
    @EnumSource(RsaKeySize.class)
    void generateRsaKeyPair(RsaKeySize keySize) throws Exception {
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKeyPair(keySize);
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, keySize.getKeySize());
    }

    @Test
    void generateDefaultRsaKeyPair() throws Exception {

        // Arrange
        RsaKeySize defaultKeySize = RsaKeySize.BIT_3072;

        // Act
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKeyPair();

        // Assert
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, defaultKeySize.getKeySize());
    }

    @Test
    void generateRsaKeyPair4096() throws Exception {
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKeyPair4096();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, RsaKeySize.BIT_4096.getKeySize());
    }

    @Test
    void generateRsaKeyPair3072() throws Exception {
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKeyPair3072();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, RsaKeySize.BIT_3072.getKeySize());
    }

    @Test
    void generateRsaKeyPair2048() throws Exception {
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKeyPair2048();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, RsaKeySize.BIT_2048.getKeySize());
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
        KeyPair keyPair = KeyGeneratorUtils.generateEd25519KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("Ed25519", keyPair.getPublic().getAlgorithm());
        assertEquals("Ed25519", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp256r1KeyPair() throws Exception {
        KeyPair keyPair = KeyGeneratorUtils.generateSecp256r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp384r1KeyPair() throws Exception {
        KeyPair keyPair = KeyGeneratorUtils.generateSecp384r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateSecp521r1KeyPair() throws Exception {
        KeyPair keyPair = KeyGeneratorUtils.generateSecp521r1KeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairWithDefaultCurve() throws Exception {
        KeyPair keyPair = KeyGeneratorUtils.generateEcKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairWithSpecificCurve() throws Exception {
        KeyPair keyPair = KeyGeneratorUtils.generateEcKeyPair(EccCurve.SECP384R1);

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateEcKeyPairThrowsExceptionForEd25519() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            KeyGeneratorUtils.generateEcKeyPair(EccCurve.ED25519);
        });

        assertTrue(exception.getMessage().contains("Ed25519"));
    }
}