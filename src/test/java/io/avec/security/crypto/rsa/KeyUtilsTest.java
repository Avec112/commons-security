package io.avec.security.crypto.rsa;

import io.avec.security.crypto.BouncyCastleProviderInitializer;
import org.apache.commons.lang3.Validate;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyUtilsTest extends BouncyCastleProviderInitializer {


    @Order(1) // run this first so it can be used by other methods
    @ParameterizedTest
    @EnumSource(KeySize.class)
    void validateRsaKeyPair(KeySize keySize) throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize.getKeySize());
        final KeyPair keyPair = generator.generateKeyPair();

        try {
            validateRsaKeyPair(keyPair, keySize);
        } catch(Exception e) {
            fail("Validation failed with " + e);
        }
    }

    @Order(2)
    @ParameterizedTest
    @CsvSource({
            "1024, 2048",
            "2048, 3072",
            "3072, 4096",
            "4096, 1024"
    })
    void validateRsaKeyPairWrongKeySize(int keySize, int expectedKeySize) throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize);
        final KeyPair keyPair = generator.generateKeyPair();

        assertThrows(RsaKeyException.class, () -> validateRsaKeyPair(keyPair, KeySize.getKeySize(expectedKeySize)));
    }

    @Order(3)
    @Test
    void validateRsaKeyPairNullArguments() {
        assertAll(
                () -> assertThrows(RsaKeyException.class, () -> validateRsaKeyPair(null, KeySize.BIT_1024)), // missing KeyPair
                () -> {
                    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
                    generator.initialize(1024);
                    assertThrows(RsaKeyException.class, () -> validateRsaKeyPair(generator.generateKeyPair(), null)); // missing size
                },
                () -> {
                    final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "BC"); // not RSA
                    generator.initialize(1024);
                    assertThrows(RsaKeyException.class, () -> validateRsaKeyPair(generator.generateKeyPair(), KeySize.BIT_1024));
                }
        );

    }

    @Test
    void generateKeyPair4096() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair4096();
        validateRsaKeyPair(keyPair, KeySize.BIT_4096);
    }

    @Test
    void generateKeyPair3072() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair3072();
        validateRsaKeyPair(keyPair, KeySize.BIT_3072);
    }

    @Test
    void generateKeyPair2048() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair2048();
        validateRsaKeyPair(keyPair, KeySize.BIT_2048);
    }

    @Test
    void generateKeyPair1024() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair1024();
        validateRsaKeyPair(keyPair, KeySize.BIT_1024);
    }

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void generateKeyPair(KeySize keySize) throws Exception {
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(keySize);
        validateRsaKeyPair(keyPair,keySize);
    }

    public void validateRsaKeyPair(KeyPair keyPair, KeySize keySize) {

        try {
            Validate.notNull(keyPair);
            Validate.notNull(keySize);
            Validate.isInstanceOf(RSAPublicKey.class, keyPair.getPublic(), "Public Key is not a RSAPublicKey");
            final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            Validate.isTrue(publicKey.getAlgorithm().equals("RSA"), "Algorithm must be RSA");
            Validate.isTrue(publicKey.getFormat().equals("X.509"), "Public key format must be X.509");
            Validate.isTrue(publicKey.getModulus().bitLength() == keySize.getKeySize(), "Key size expected to be %s", keySize.getKeySize());

            Validate.isInstanceOf(RSAPrivateKey.class, keyPair.getPrivate(), "Private Key is not a RSAPrivateKey");
            final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            Validate.isTrue(privateKey.getAlgorithm().equals("RSA"), "Algorithm must be RSA");
            Validate.isTrue(privateKey.getFormat().equals("PKCS#8"), "Private key format must be PKCS#8");
            Validate.isTrue(privateKey.getModulus().bitLength() == keySize.getKeySize(), "Key size expected to be %s", keySize.getKeySize());
        } catch(Exception e) {
            throw new RsaKeyException(e.getMessage());
        }
    }
}