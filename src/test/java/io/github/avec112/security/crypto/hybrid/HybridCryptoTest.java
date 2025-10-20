package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.*;
import io.github.avec112.security.crypto.rsa.KeyUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;


class HybridCryptoTest {

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = KeyUtils.generateRsaKeyPair();
    }

    @Test
    void defaultEncryptionAndDecryption() throws Exception {
        final PlainText plainText = new PlainText("plainText");

        // Encrypt
        HybridEncryptionResult hybridEncryptionResult = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .build();

        // Decrypt
        PlainText plainTextResult = DecryptBuilder.decryptionBuilder()
                .key(keyPair.getPrivate())
                .encryptedSymmetricalKey(hybridEncryptionResult.getEncryptedSymmetricalKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .build();


        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText().getValue()).isNotEqualTo(plainText.getValue()),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionStrength()).isEqualTo(EncryptionStrength.BIT_128),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionMode()).isEqualTo(EncryptionMode.GCM),
                () -> assertThat(hybridEncryptionResult.getEncryptedSymmetricalKey()).isNotBlank(),
                () -> assertThat(plainTextResult).isEqualTo(plainText)
        );

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
    void encryptAndDecrypt(String mode, int strength) throws Exception {
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final EncryptionStrength encryptionStrength = EncryptionStrength.getAESKeyLength(strength);
        final PlainText plainText = new PlainText("plainText");

        // Encrypt
        HybridEncryptionResult hybridEncryptionResult = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .optional(encryptionMode)
                .optional(encryptionStrength)
                .build();

        // Decrypt
        PlainText plainTextResult = DecryptBuilder.decryptionBuilder()
                .key(keyPair.getPrivate())
                .encryptedSymmetricalKey(hybridEncryptionResult.getEncryptedSymmetricalKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .optional(encryptionMode)
                .optional(encryptionStrength)
                .build();

        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText().getValue()).isNotEqualTo(plainText.getValue()),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionStrength()).isEqualTo(encryptionStrength),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionMode()).isEqualTo(encryptionMode),
                () -> assertThat(hybridEncryptionResult.getEncryptedSymmetricalKey()).isNotBlank(),
                () -> assertThat(plainTextResult).isEqualTo(plainText)
        );


    }

    @Test
    void encryptionException() {
        assertAll(
                () -> assertThrows(Exception.class, () -> EncryptBuilder.encryptionBuilder().build()), // missing PublicKey and plainText
                () -> assertThrows(Exception.class, () -> EncryptBuilder.encryptionBuilder().key(keyPair.getPublic()).build()) // missing plainText
        );
    }

    /**
     * Testing DecryptBuilder.decryptionBuilder() with missing arguments
     */
    @Test
    void decryptionException() {
        DecryptBuilder builder = DecryptBuilder.decryptionBuilder();
        assertAll(
                () -> assertThrows(MultipleMissingArgumentsError.class, builder::build),
                () -> assertThrows(MissingPrivateKeyException.class, () -> builder.key(null).build()),
                () -> assertThrows(MissingPrivateKeyException.class, () -> builder.cipherText(new CipherText("cipherText")).encryptedSymmetricalKey("symKey").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).build()),
                () -> assertThrows(MissingCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(null).build()),
                () -> assertThrows(BlankCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("")).build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).encryptedSymmetricalKey("symKey").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedSymmetricalKey(null).build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedSymmetricalKey("").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedSymmetricalKey("symKey").build())
        );
    }

}