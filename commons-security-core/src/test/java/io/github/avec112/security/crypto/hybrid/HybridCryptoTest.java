package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.KeyGeneratorUtil;
import io.github.avec112.security.crypto.aes.AesKeySize;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.*;
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
        keyPair = KeyGeneratorUtil.generateRsaKeyPair();
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
                .encryptedKey(hybridEncryptionResult.getEncryptedKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .build();


        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText().getValue()).isNotEqualTo(plainText.getValue()),
                () -> assertThat(hybridEncryptionResult.getAesKeySize()).isEqualTo(AesKeySize.BIT_256),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionMode()).isEqualTo(EncryptionMode.GCM),
                () -> assertThat(hybridEncryptionResult.getEncryptedKey()).isNotBlank(),
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
    void encryptAndDecrypt(String mode, int keySize) throws Exception {
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final AesKeySize aesKeySize = AesKeySize.getKeySize(keySize);
        final PlainText plainText = new PlainText("plainText");

        // Encrypt
        HybridEncryptionResult hybridEncryptionResult = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .build();

        // Decrypt
        PlainText plainTextResult = DecryptBuilder.decryptionBuilder()
                .key(keyPair.getPrivate())
                .encryptedKey(hybridEncryptionResult.getEncryptedKey())
                .cipherText(hybridEncryptionResult.getCipherText())
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .build();

        assertAll(
                () -> assertThat(hybridEncryptionResult.getCipherText().getValue()).isNotEqualTo(plainText.getValue()),
                () -> assertThat(hybridEncryptionResult.getAesKeySize()).isEqualTo(aesKeySize),
                () -> assertThat(hybridEncryptionResult.getAesEncryptionMode()).isEqualTo(encryptionMode),
                () -> assertThat(hybridEncryptionResult.getEncryptedKey()).isNotBlank(),
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
                () -> assertThrows(MissingPrivateKeyException.class, () -> builder.cipherText(new CipherText("cipherText")).encryptedKey("symKey").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).build()),
                () -> assertThrows(MissingCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(null).build()),
                () -> assertThrows(BlankCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("")).build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).encryptedKey("symKey").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedKey(null).build()),
                () -> assertThrows(MissingEncryptedSymmetricalKeyException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedKey("").build()),
                () -> assertThrows(BadCipherTextException.class, () -> builder.key(keyPair.getPrivate()).cipherText(new CipherText("cipherText")).encryptedKey("symKey").build())
        );
    }

    // ========== JSON Serialization Tests ==========

    @Test
    void toJson_shouldSerializeToValidJson() throws Exception {
        final PlainText plainText = new PlainText("Test data for JSON");

        HybridEncryptionResult result = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .build();

        String json = result.toJson();

        assertThat(json).isNotNull()
                .contains("\"version\"")
                .contains("\"cipherText\"")
                .contains("\"encryptedKey\"")
                .contains("\"aesEncryptionMode\"")
                .contains("\"aesKeySize\"");
    }

    @Test
    void fromJson_shouldDeserializeCorrectly() throws Exception {
        final PlainText plainText = new PlainText("Test data for JSON roundtrip");

        // Encrypt
        HybridEncryptionResult original = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .withMode(EncryptionMode.GCM)
                .withKeySize(AesKeySize.BIT_256)
                .build();

        // Serialize to JSON
        String json = original.toJson();

        // Deserialize from JSON
        HybridEncryptionResult deserialized = HybridEncryptionResult.fromJson(json);

        assertAll(
                () -> assertThat(deserialized.getVersion()).isEqualTo("1.0"),
                () -> assertThat(deserialized.getCipherText()).isEqualTo(original.getCipherText()),
                () -> assertThat(deserialized.getEncryptedKey()).isEqualTo(original.getEncryptedKey()),
                () -> assertThat(deserialized.getAesEncryptionMode()).isEqualTo(EncryptionMode.GCM),
                () -> assertThat(deserialized.getAesKeySize()).isEqualTo(AesKeySize.BIT_256)
        );
    }

    @Test
    void jsonRoundtrip_shouldPreserveDecryptionCapability() throws Exception {
        final PlainText expected = new PlainText("Test data for full roundtrip");

        // Encrypt
        HybridEncryptionResult encrypted = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(expected)
                .build();

        // Serialize to JSON and back
        String json = encrypted.toJson();
        HybridEncryptionResult deserialized = HybridEncryptionResult.fromJson(json);

        // Decrypt using deserialized result
        PlainText decrypted = DecryptBuilder.decryptionBuilder()
                .key(keyPair.getPrivate())
                .cipherText(deserialized.getCipherText())
                .encryptedKey(deserialized.getEncryptedKey())
                .withMode(deserialized.getAesEncryptionMode())
                .withKeySize(deserialized.getAesKeySize())
                .build();

        assertThat(decrypted).isEqualTo(expected);
    }

    @Test
    void toJson_shouldIncludeVersionField() throws Exception {
        final PlainText plainText = new PlainText("Version test");

        HybridEncryptionResult result = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .build();

        assertThat(result.getVersion()).isEqualTo("1.0");
        assertThat(result.toJson()).contains("\"version\": \"1.0\"");
    }

    @ParameterizedTest
    @CsvSource({
            "GCM, 128, GCM@128-bit",
            "GCM, 192, GCM@192-bit",
            "GCM, 256, GCM@256-bit",
            "CTR, 128, CTR@128-bit",
            "CTR, 192, CTR@192-bit",
            "CTR, 256, CTR@256-bit"
    })
    void describe_shouldReturnHumanReadableFormat(String mode, int keySize, String expected) throws Exception {
        final PlainText plainText = new PlainText("Test data");
        final EncryptionMode encryptionMode = EncryptionMode.valueOf(mode);
        final AesKeySize aesKeySize = AesKeySize.getKeySize(keySize);

        HybridEncryptionResult result = EncryptBuilder.encryptionBuilder()
                .key(keyPair.getPublic())
                .plainText(plainText)
                .withMode(encryptionMode)
                .withKeySize(aesKeySize)
                .build();

        assertThat(result.describe()).isEqualTo(expected);
    }

}