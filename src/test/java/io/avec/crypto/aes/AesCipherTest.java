package io.avec.crypto.aes;

import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AesCipherTest {


    @Order(1)
    @ParameterizedTest
    @CsvSource({
            "CTR, 128",
            "CTR, 192",
            "CTR, 256",
            "GCM, 128",
            "GCM, 192",
            "GCM, 256"
    })
    void testAesCipherConstructors(String mode, int strength) {
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final EncryptionStrength encryptionStrength = EncryptionStrength.getAESKeyLength(strength);

        final AesCipher aesCipher1 = new AesCipher(mode, strength); // string + int
        final AesCipher aesCipher2 = new AesCipher(encryptionMode, encryptionStrength); // enums

        validateAesCipher(encryptionMode, encryptionStrength, aesCipher1);
        validateAesCipher(encryptionMode, encryptionStrength, aesCipher2);
    }

    @Test
    void testAesCipherDefaultConstructor() {
        AesCipher aesCipher = new AesCipher();
        validateAesCipher(EncryptionMode.GCM, EncryptionStrength.BIT_256, aesCipher);
    }


    private void validateAesCipher(EncryptionMode encryptionMode, EncryptionStrength encryptionStrength, AesCipher aesCipher) {
        assertEquals(encryptionMode, aesCipher.getAlgorithm());
        assertEquals(encryptionStrength, aesCipher.getKeyLength());
    }

    @ParameterizedTest
    @CsvSource({
            "CTR, 128",
            "CTR, 192",
            "CTR, 256",
            "GCM, 128",
            "GCM, 192",
            "GCM, 256"
    })
    void testAesCipher(String encryptionMode, int encryptionStrength) throws Exception {
        final AesCipher aesCipher = new AesCipher(encryptionMode, encryptionStrength);
        final PlainText plaintextOriginal = new PlainText("Secret text");
        final Password password = new Password("password");

        // encrypt
        CipherText cipherText = aesCipher.encrypt(plaintextOriginal, password);

        // decrypt
        PlainText plainText = aesCipher.decrypt(cipherText, password);

        assertEquals(plaintextOriginal, plainText);
    }
}