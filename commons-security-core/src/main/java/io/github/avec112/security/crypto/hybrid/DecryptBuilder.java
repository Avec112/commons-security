package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.AesDecryptor;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BlankCipherTextException;
import io.github.avec112.security.crypto.error.MissingCipherTextException;
import io.github.avec112.security.crypto.error.MissingEncryptedSymmetricalKeyException;
import io.github.avec112.security.crypto.error.MissingPrivateKeyException;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.validate.Validate;

import java.security.PrivateKey;

/**
 * The DecryptBuilder class is used to build decryption operations in a fluent way.
 * It provides methods to set the necessary parameters for decryption and to perform the decryption operation.
 */
public class DecryptBuilder {

    private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
    private EncryptionMode encryptionMode = EncryptionMode.GCM;

    private String encryptedKey;
    private CipherText cipherText;

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

    public DecryptBuilder encryptedKey(String encryptedKey) {
        Validate.nonBlank(encryptedKey, MissingEncryptedSymmetricalKeyException::new);
        this.encryptedKey = encryptedKey;
        return this;
    }

    public DecryptBuilder cipherText(CipherText cipherText) {
        Validate.nonNull(cipherText, MissingCipherTextException::new);
        Validate.nonBlank(cipherText.getValue(), BlankCipherTextException::new);
        this.cipherText = cipherText;
        return this;
    }

    public PlainText build() throws Exception {
        Validate.all(
                () -> Validate.nonNull(privateKey, MissingPrivateKeyException::new),
                () -> Validate.nonBlank(encryptedKey, MissingEncryptedSymmetricalKeyException::new),
                () -> Validate.nonNull(cipherText, MissingCipherTextException::new),
                () -> Validate.nonBlank(cipherText.getValue(), BlankCipherTextException::new)
        );

        final RsaCipher rsaCipher = new RsaCipher();
        final PlainText symKey = rsaCipher.decrypt(new CipherText(encryptedKey), privateKey);
        return AesDecryptor.withPasswordAndCipherText(new Password(symKey.getValue()), cipherText)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .decrypt();
    }

    public DecryptBuilder withMode(EncryptionMode encryptionMode) {
        Validate.nonNull(encryptionMode, "encryptionMode");
        this.encryptionMode = encryptionMode;
        return this;
    }

    public DecryptBuilder withStrength(EncryptionStrength encryptionStrength) {
        Validate.nonNull(encryptionStrength, "encryptionStrength");
        this.encryptionStrength = encryptionStrength;
        return this;
    }

}
