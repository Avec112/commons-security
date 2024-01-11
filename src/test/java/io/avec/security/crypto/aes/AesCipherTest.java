package io.avec.security.crypto.aes;

import io.avec.security.crypto.domain.CipherText;
import io.avec.security.crypto.domain.Password;
import io.avec.security.crypto.domain.PlainText;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AesCipherTest {


    @Test
    void aesDefaultWithObjects() throws Exception {

        // Arrange
        final PlainText plaintextExpected = new PlainText("My secret text!");
        final Password password = new Password("SecretPassword123");

        // Act
        CipherText cipherText = AesCipher.withPassword(password)
                .encrypt(plaintextExpected);

        PlainText plainTextActual = AesCipher.withPassword(password)
                .decrypt(cipherText);

        // Assert
        assertThat(plainTextActual).isEqualTo(plaintextExpected);
    }

    @Test
    void aesDefaultWithStrings() throws Exception {

        // Arrange
        final String plaintextExpected = "My secret text!";
        final String password = "SecretPassword123";

        // Act
        String cipherText = AesCipher.withPassword(password)
                .encrypt(plaintextExpected);

        String plainTextActual = AesCipher.withPassword(password)
                .decrypt(cipherText);

        // Assert
        assertThat(plainTextActual).isEqualTo(plaintextExpected);
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
    void aesMoreConfigWithObjects(String mode, int strength) throws Exception {
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final EncryptionStrength encryptionStrength = EncryptionStrength.getAESKeyLength(strength);
        final PlainText plaintextOriginal = new PlainText("Secret text");
        final Password password = new Password("password");

        // encrypt
        CipherText cipherText = AesCipher.withPassword(password)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .encrypt(plaintextOriginal);

        // decrypt
        PlainText plainText = AesCipher.withPassword(password)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .decrypt(cipherText);

        assertThat(plaintextOriginal).isEqualTo(plainText);
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
    void aesMoreConfigWithStrings(String mode, int strength) throws Exception {

        // Arrange
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final EncryptionStrength encryptionStrength = EncryptionStrength.getAESKeyLength(strength);
        final String secret = "My secret text!";
        final String password = "SecretPassword123";

        // Act
        String cipherText = AesCipher.withPassword(password)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .encrypt(secret);

        String plainText = AesCipher.withPassword(password)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .decrypt(cipherText);

        // Assert
        assertThat(plainText).isEqualTo(secret);
    }
}