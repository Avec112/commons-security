package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AesCipherTest {

    @Test
    void aesDefaultWithStrings() throws Exception {

        // Arrange
        final PlainText plaintextExpected = new PlainText("My secret text!");
        final Password password = new Password("SecretPassword123");

        // Act
        CipherText cipherText = AesEncryptor.withPasswordAndText(password, plaintextExpected)
                .encrypt();

        PlainText plainTextActual = AesDecryptor.withPasswordAndCipherText(password, cipherText)
                .decrypt();

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
    void aesMoreConfigWithObjects(String mode, int keySize) throws Exception {
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final AesKeySize aesKeySize = AesKeySize.getKeySize(keySize);
        final PlainText plaintextOriginal = new PlainText("Secret text");
        final Password password = new Password("password");

        // encrypt
        CipherText cipherText = AesEncryptor.withPasswordAndText(password, plaintextOriginal)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .encrypt();

        // decrypt
        PlainText plainTextResult = AesDecryptor.withPasswordAndCipherText(password, cipherText)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .decrypt();

        assertThat(plaintextOriginal).isEqualTo(plainTextResult);
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
    void aesMoreConfigWithStrings(String mode, int keySize) throws Exception {

        // Arrange
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final AesKeySize aesKeySize = AesKeySize.getKeySize(keySize);
        final PlainText plaintextOriginal = new PlainText("My secret text!");
        final Password password = new Password("OtherPassword123");

        // Act
        CipherText cipherText = AesEncryptor.withPasswordAndText(password, plaintextOriginal)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .encrypt();

        PlainText plainTextResult = AesDecryptor.withPasswordAndCipherText(password, cipherText)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .decrypt();

        // Assert
        assertThat(plainTextResult).isEqualTo(plaintextOriginal);
    }
}