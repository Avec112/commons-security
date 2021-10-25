package io.avec.crypto.rsa;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyUtilsTest {

    @Order(1) // run this first so it can be used by other methods
    @ParameterizedTest
    @CsvSource({
            "1024",
            "2048",
            "4096"
    })
    void validateRsaKeyPair(int keySize) throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        final KeyPair keyPair = generator.generateKeyPair();

        try {
            KeyUtils.validateRsaKeyPair(keyPair, KeySize.getKeySize(keySize));
        } catch(Exception e) {
            fail("Validation failed with " + e);
        }
    }

    @Order(2)
    @ParameterizedTest
    @CsvSource({
            "1024, 2048",
            "2048, 4096",
            "4096, 1024"
    })
    void validateRsaKeyPairWrongKeySize(int keySize, int expectedKeySize) throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        final KeyPair keyPair = generator.generateKeyPair();

        assertThrows(RsaKeyException.class, () -> KeyUtils.validateRsaKeyPair(keyPair, KeySize.getKeySize(expectedKeySize)));
    }

    @Order(3)
    @Test
    void validateRsaKeyPairNullArguments() {
        assertAll(
                () -> assertThrows(RsaKeyException.class, () -> KeyUtils.validateRsaKeyPair(null, KeySize.BIT_1024)), // missing KeyPair
                () -> {
                    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(1024);
                    assertThrows(RsaKeyException.class, () -> KeyUtils.validateRsaKeyPair(generator.generateKeyPair(), null)); // missing size
                },
                () -> {
                    final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA"); // not RSA
                    generator.initialize(1024);
                    assertThrows(RsaKeyException.class, () -> KeyUtils.validateRsaKeyPair(generator.generateKeyPair(), KeySize.BIT_1024));
                }
        );

    }

    @Test
    void generateKeyPair4096() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair4096();
        KeyUtils.validateRsaKeyPair(keyPair, KeySize.BIT_4096);
    }

    @Test
    void generateKeyPair2048() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair2048();
        KeyUtils.validateRsaKeyPair(keyPair, KeySize.BIT_2048);
    }

    @Test
    void generateKeyPair1024() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair1024();
        KeyUtils.validateRsaKeyPair(keyPair, KeySize.BIT_1024);
    }

    @ParameterizedTest
    @CsvSource({
            "1024",
            "2048",
            "4096"
    })
    void generateKeyPair(int keySize) throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeyPair(KeySize.getKeySize(keySize));
        KeyUtils.validateRsaKeyPair(keyPair, KeySize.getKeySize(keySize));
    }
}