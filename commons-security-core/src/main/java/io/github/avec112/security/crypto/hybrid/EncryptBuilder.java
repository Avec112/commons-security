package io.github.avec112.security.crypto.hybrid;


import io.github.avec112.security.crypto.aes.AesEncryptor;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BlankPlainTextException;
import io.github.avec112.security.crypto.error.MissingPlainTextException;
import io.github.avec112.security.crypto.error.MissingPublicKeyException;
import io.github.avec112.security.crypto.random.RandomUtils;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.validate.Validate;

import java.security.PublicKey;

/**
 * The {@code EncryptBuilder} class provides a fluent API for performing hybrid encryption.
 * <p>
 * This hybrid scheme combines two cryptographic algorithms:
 * <ul>
 *   <li><b>RSA/ECB/OAEPWithSHA-256AndMGF1Padding</b> (RSA-OAEP-SHA256) — used to encrypt
 *       the randomly generated AES password. This provides secure key encapsulation with
 *       modern OAEP padding.</li>
 *   <li><b>AES-GCM</b> or <b>AES-CTR</b> — used to encrypt the actual data payload, providing
 *       confidentiality and integrity protection.</li>
 * </ul>
 * <p>
 * The result is a {@link HybridEncryptionResult} that contains:
 * <ul>
 *   <li>The AES-encrypted cipher text</li>
 *   <li>The RSA-encrypted AES password</li>
 *   <li>Metadata describing the chosen AES mode and strength</li>
 * </ul>
 * <p>
 * Example usage:
 * <pre>{@code
 * HybridEncryptionResult result = EncryptBuilder.encryptionBuilder()
 *     .key(publicKey)
 *     .plainText(new PlainText("Sensitive message"))
 *     .optional(EncryptionMode.GCM)
 *     .optional(EncryptionStrength.BIT_256)
 *     .build();
 * }</pre>
 * <p>
 * This class automatically uses the modern RSA-OAEP-SHA256 transformation internally via {@link RsaCipher}.
 */
public class EncryptBuilder {
    private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
    private EncryptionMode encryptionMode = EncryptionMode.GCM;

    private PlainText plainText;
    private PublicKey publicKey;

    private EncryptBuilder() {
    }

    /**
     * Returns a builder for encryption operations.
     *
     * @return the EncryptBuilder instance
     */
    public static EncryptBuilder encryptionBuilder() {
        return new EncryptBuilder();
    }

    /**
     * Sets the public key to be used for encryption.
     *
     * @param publicKey the public key to be used for encryption
     * @return the EncryptBuilder object
     */
    public EncryptBuilder key(PublicKey publicKey) {
        Validate.nonNull(publicKey, MissingPublicKeyException::new);
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Sets the plain text to be encrypted.
     *
     * @param plainText the plain text to be encrypted
     * @return the EncryptBuilder object
     */
    public EncryptBuilder plainText(PlainText plainText) {
        Validate.nonBlank(plainText.getValue(), BlankPlainTextException::new);
        this.plainText = plainText;
        return this;
    }

    /**
     * Builds a HybridEncryptionResult object using the provided parameters.
     *
     * @throws Exception if publicKey or plainText is null or blank
     * @return the HybridEncryptionResult object
     */
    public HybridEncryptionResult build() throws Exception {
        Validate.nonNull(publicKey, MissingPublicKeyException::new);
        Validate.nonNull(plainText, MissingPlainTextException::new);
        Validate.nonBlank(plainText.getValue(), BlankPlainTextException::new);


        final String randomPassword = RandomUtils.randomString(20);
        final String rsaEncryptedKey = rsaEncryptedKey(publicKey, randomPassword);
        final CipherText cipherText = AesEncryptor.withPasswordAndText(new Password(randomPassword), plainText)
                .withMode(encryptionMode)
                .withStrength(encryptionStrength)
                .encrypt();

        return new HybridEncryptionResult(cipherText, rsaEncryptedKey, encryptionMode, encryptionStrength);
    }


    /**
     * Sets the optional encryption mode for the EncryptBuilder object.
     *
     * @param encryptionMode The encryption mode to set. Valid values are EncryptionMode.GCM or EncryptionMode.CTR.
     * @return The EncryptBuilder object with the encryption mode set.
     */
    public EncryptBuilder withMode(EncryptionMode encryptionMode) {
        Validate.nonNull(encryptionMode, "encryptionMode");
        this.encryptionMode = encryptionMode;
        return this;
    }

    /**
     * Sets the optional encryption strength for the EncryptBuilder object.
     *
     * @param encryptionStrength The encryption strength to set.
     * @return The EncryptBuilder object with the encryption strength set.
     * @throws NullPointerException if encryptionStrength is null
     */
    public EncryptBuilder withStrength(EncryptionStrength encryptionStrength) {
        Validate.nonNull(encryptionStrength, "encryptionStrength");
        this.encryptionStrength = encryptionStrength;
        return this;
    }

    /**
     * Encrypts a random password using the provided public key.
     *
     * @param publicKey         the public key to use for encryption
     * @param randomPassword    the random password to encrypt
     * @return the encrypted random password as a string
     * @throws Exception if encryption fails
     */
    private String rsaEncryptedKey(PublicKey publicKey, String randomPassword) throws Exception {
        RsaCipher rsaCipher = new RsaCipher();
        final CipherText rsaEncryptedKey = rsaCipher.encrypt(new PlainText(randomPassword), publicKey);
        return rsaEncryptedKey.getValue();

    }

}
