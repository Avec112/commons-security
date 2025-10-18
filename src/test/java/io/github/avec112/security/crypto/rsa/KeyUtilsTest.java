package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    void generateKeyPair4096() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair4096();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_4096.getKeySize());
    }

    @Test
    void generateKeyPair3072() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair3072();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_3072.getKeySize());
    }

    @Test
    void generateKeyPair2048() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair2048();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_2048.getKeySize());
    }

    @Test
    void generateKeyPair1024() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair1024();
        assertKeyPairNotNull(keyPair);
        assertKeyPairBitLengthEquals(keyPair, KeySize.BIT_1024.getKeySize());
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
}