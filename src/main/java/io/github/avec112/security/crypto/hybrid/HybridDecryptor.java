package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.AesCipher;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BlankCipherTextException;
import io.github.avec112.security.crypto.error.MissingEncryptedSymmetricalKeyException;
import io.github.avec112.security.crypto.error.MissingPrivateKeyException;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.validate.Validate;

import java.security.PrivateKey;

public class DecryptBuilder {

    private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
    private EncryptionMode encryptionMode = EncryptionMode.GCM;

    private String encryptedSymmetricalKey;
    private String cipherText;

    private PrivateKey privateKey;

    private DecryptBuilder() {
    }

    /**
     * Creates a builder for decryption operations.
     *
     * @return a DecryptBuilder instance
     */
    public static DecryptBuilder decryptionBuilder() {
        return new DecryptBuilder();
    }

    public DecryptBuilder key(PrivateKey privateKey) {
        Validate.nonNull(privateKey, MissingPrivateKeyException::new);
        this.privateKey = privateKey;
        return this;
    }

    public DecryptBuilder encryptedSymmetricalKey(String encryptedSymmetricalKey) {
        Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new);
        this.encryptedSymmetricalKey = encryptedSymmetricalKey;
        return this;
    }

    public DecryptBuilder cipherText(String cipherText) {
        Validate.nonBlank(cipherText, BlankCipherTextException::new);
        this.cipherText = cipherText;
        return this;
    }

    public String build() throws Exception {
        Validate.all(
                () -> Validate.nonNull(privateKey, MissingPrivateKeyException::new),
                () -> Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new),
                () -> Validate.nonBlank(cipherText, BlankCipherTextException::new)
        );

        final RsaCipher rsaCipher = new RsaCipher();
        final PlainText symKey = rsaCipher.decrypt(new CipherText(encryptedSymmetricalKey), privateKey);
        return new AesCipher.Builder(symKey.getValue())
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .decrypt(cipherText);
    }

    public DecryptBuilder optional(EncryptionMode encryptionMode) {
        Validate.nonNull(encryptionMode, "encryptionMode");
        this.encryptionMode = encryptionMode;
        return this;
    }

    public DecryptBuilder optional(EncryptionStrength encryptionStrength) {
        Validate.nonNull(encryptionStrength, "encryptionStrength");
        this.encryptionStrength = encryptionStrength;
        return this;
    }

}
