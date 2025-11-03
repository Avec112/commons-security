package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.encoding.EncodingUtil;
import lombok.Getter;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * A class that provides AES encryption functionality.
 */
@Getter
public class AesEncryptor {

    private final Password password;
    private final PlainText plainText;
    private static final int SALT_LENGTH_BYTE = 16;
    private EncryptionMode mode = EncryptionMode.GCM; // default value
    private AesKeySize aesKeySize = AesKeySize.BIT_256; // default value

    private AesEncryptor(Password password, PlainText plainText) {
        this.password = password;
        this.plainText = plainText;
    }

    /**
     * Creates a new instance of AesEncryptor with the given password and plain text.
     *
     * @param password The password for encryption. Cannot be null or blank.
     * @param plainText The plain text to be encrypted. Cannot be null or blank.
     * @return A new instance of AesEncryptor.
     * @throws IllegalArgumentException if either password or plainText is null or blank.
     */
    public static AesEncryptor withPasswordAndText(Password password, PlainText plainText) {
        Validate.notNull(password, "Password cannot be null");
        Validate.notNull(plainText, "PlainText cannot be null");
        Validate.notBlank(password.getValue(), "Password cannot be blank");
        Validate.notBlank(plainText.getValue(), "PlainText cannot be blank");

        return new AesEncryptor(password, plainText);
    }

    /**
     * Sets the encryption mode for the AES encryptor.
     *
     * @param mode The encryption mode. Cannot be null.
     * @return The AES encryptor instance.
     * @throws IllegalArgumentException if mode is null.
     */
    public AesEncryptor withMode(EncryptionMode mode) {
        Validate.notNull(mode, "Encryption mode cannot be null");
        this.mode = mode;

        return this; // for chaining
    }

    /**
     * Sets the encryption keySize for the AES encryptor.
     *
     * @param aesKeySize The encryption keySize to set. Cannot be null.
     * @return The AES encryptor instance for method chaining.
     * @throws IllegalArgumentException if the aesKeySize is null.
     */
    public AesEncryptor withKeySize(AesKeySize aesKeySize) {
        Validate.notNull(aesKeySize, "Encryption aesKeySize cannot be null");
        this.aesKeySize = aesKeySize;

        return this; // for chaining
    }

    /**
     * Encrypts the plain text using AES encryption.
     *
     * @return The cipher text.
     * @throws BadCipherConfigurationException if there is an error in the cipher configuration.
     */
    public CipherText encrypt() throws BadCipherConfigurationException {
        try {

            final byte[] cipherText = encryptPlainText(plainText, password);
            final String cipherTextEncoded = EncodingUtil.base64Encode(cipherText);
            return new CipherText(cipherTextEncoded);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e);
        }
    }

    /**
     * Encrypts the given plain text using AES encryption with the provided password.
     *
     * @param plainText The plain text to be encrypted. Cannot be null.
     * @param password  The password for encryption. Cannot be null.
     * @return The encrypted cipher text.
     */
    private byte[] encryptPlainText(PlainText plainText, Password password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] salt = AesUtil.getRandomNonce(SALT_LENGTH_BYTE);
        byte[] iv = AesUtil.getRandomNonce(getMode().getIvLength());

        Charset encoding = StandardCharsets.UTF_8;
        int encryptionMode = Cipher.ENCRYPT_MODE;

        Cipher cipher = AesUtil.createCipher(password, salt, iv, encryptionMode, getMode(), getAesKeySize().getKeySize());
        byte[] cText = cipher.doFinal(plainText.getValue().getBytes(encoding));

        return ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
    }
}
