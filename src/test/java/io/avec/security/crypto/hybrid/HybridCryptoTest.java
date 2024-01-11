package io.avec.security.crypto.hybrid;

import io.avec.security.crypto.aes.EncryptionMode;
import io.avec.security.crypto.aes.EncryptionStrength;
import io.avec.security.crypto.error.*;
import io.avec.security.crypto.rsa.KeyUtils;
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
        keyPair = KeyUtils.generateKeyPair1024();
    }

    @Test
    void defaultEncryptionAndDecryption() throws Exception {
        final String plainText = "plainText";

        // Encrypt
        HybridEncryptionResult hybridEncryptionResult = HybridCrypto.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .build();

        // Decrypt
        String plainTextResult = HybridCrypto.decryptionBuilder()
                .key(keyPair.getPrivate())
                .encryptedSymmetricalKey(hybridEncryptionResult.getEncryptedSymmetricalKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .build();


        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText()).isNotEqualTo(plainText),
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
        final String plainText = "plainText";

        // Encrypt
        HybridEncryptionResult hybridEncryptionResult = HybridCrypto.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .optional(encryptionMode)
                .optional(encryptionStrength)
                .build();

        // Decrypt
        String plainTextResult = HybridCrypto.decryptionBuilder()
                .key(keyPair.getPrivate())
                .encryptedSymmetricalKey(hybridEncryptionResult.getEncryptedSymmetricalKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .optional(encryptionMode)
                .optional(encryptionStrength)
                .build();

        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText()).isNotEqualTo(plainText),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionStrength()).isEqualTo(encryptionStrength),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionMode()).isEqualTo(encryptionMode),
                () -> assertThat(hybridEncryptionResult.getEncryptedSymmetricalKey()).isNotBlank(),
                () -> assertThat(plainTextResult).isEqualTo(plainText)
        );


    }

    @Test
    void encryptionException() {
        assertAll(
                () -> assertThrows(Exception.class, () -> HybridCrypto.encryptionBuilder().build()), // missing PublicKey and plainText
                () -> assertThrows(Exception.class, () -> HybridCrypto.encryptionBuilder().key(keyPair.getPublic()).build()) // missing plainText
        );
    }

    /**
     * Testing HybridCrypto.decryptionBuilder() with missing arguments
     */
    @Test
    void decryptionException() {
        assertAll(
                () -> assertThrows(MultipleMissingArgumentsError.class, () -> HybridCrypto.decryptionBuilder().build()),
                () -> assertThrows(MissingPrivateKeyException.class, () -> HybridCrypto.decryptionBuilder().key(null).build()),
                () -> assertThrows(MissingPrivateKeyException.class, () -> HybridCrypto.decryptionBuilder().cipherText("cipherText").encryptedSymmetricalKey("symKey").build()),
                () -> assertThrows(MultipleMissingArgumentsError.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).build()),
                () -> assertThrows(MissingCipherTextException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText(null).build()),
                () -> assertThrows(MissingCipherTextException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText("").build()),
                () -> assertThrows(MissingCipherTextException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).encryptedSymmetricalKey("symKey").build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText("cipherText").build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText("cipherText").encryptedSymmetricalKey(null).build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText("cipherText").encryptedSymmetricalKey("").build()),
                () -> assertThrows(BadCipherTextException.class, () -> HybridCrypto.decryptionBuilder().key(keyPair.getPrivate()).cipherText("cipherText").encryptedSymmetricalKey("symKey").build())
        );
    }

}