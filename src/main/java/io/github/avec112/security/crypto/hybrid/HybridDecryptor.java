package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.AesDecryptor;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.MissingCipherTextException;
import io.github.avec112.security.crypto.error.MissingEncryptedSymmetricalKeyException;
import io.github.avec112.security.crypto.error.MissingPrivateKeyException;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.validate.Validate;

import java.security.PrivateKey;

public class HybridDecryptor {

    private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
    private EncryptionMode encryptionMode = EncryptionMode.GCM;

    private String encryptedSymmetricalKey;
    private String cipherText;

    private PrivateKey privateKey;

    private HybridDecryptor() {
    }

    /**
     * Creates a builder for decryption operations.
     *
     * @return a HybridDecryptor instance
     */
    public static HybridDecryptor decryptionBuilder() {
        return new HybridDecryptor();
    }

    public HybridDecryptor key(PrivateKey privateKey) {
        Validate.nonNull(privateKey, MissingPrivateKeyException::new);
        this.privateKey = privateKey;
        return this;
    }

    public HybridDecryptor encryptedSymmetricalKey(String encryptedSymmetricalKey) {
        Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new);
        this.encryptedSymmetricalKey = encryptedSymmetricalKey;
        return this;
    }

    public HybridDecryptor cipherText(String cipherText) {
        Validate.nonBlank(cipherText, MissingCipherTextException::new);
        this.cipherText = cipherText;
        return this;
    }

    public String build() throws Exception {
        Validate.all(
                () -> Validate.nonNull(privateKey, MissingPrivateKeyException::new),
                () -> Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new),
                () -> Validate.nonBlank(cipherText, MissingCipherTextException::new)
        );

        final RsaCipher rsaCipher = new RsaCipher();
        final PlainText symKey = rsaCipher.decrypt(new CipherText(encryptedSymmetricalKey), privateKey);
        return AesDecryptor.withPasswordAndCipherText(new Password(symKey.getValue()), new CipherText(cipherText))
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .decrypt().getValue();
    }

    public HybridDecryptor withEncryptionMode(EncryptionMode encryptionMode) {
        Validate.nonNull(encryptionMode, "encryptionMode");
        this.encryptionMode = encryptionMode;
        return this;
    }

    public HybridDecryptor withEncryptionStrength(EncryptionStrength encryptionStrength) {
        Validate.nonNull(encryptionStrength, "encryptionStrength");
        this.encryptionStrength = encryptionStrength;
        return this;
    }

}
