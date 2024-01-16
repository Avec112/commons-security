package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.crypto.error.BadCipherTextException;
import io.github.avec112.security.encoding.EncodingUtils;
import lombok.Getter;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * The AesCipher class provides AES encryption and decryption functionality.
 */
@Getter
public class AesCipher  {

    private static final int SALT_LENGTH_BYTE = 16;
    private EncryptionMode algorithm = EncryptionMode.GCM;
    private EncryptionStrength keyLength = EncryptionStrength.BIT_256;

    private AesCipher(){}

    /**
     * Encrypts a given plain text using AES encryption algorithm.
     *
     * @param plainText The plain text to be encrypted.
     * @param password The password used to generate the secret key.
     * @return The cipher text obtained after encryption.
     * @throws BadCipherConfigurationException If the encryption configuration is invalid.
     */
    public CipherText encrypt(PlainText plainText, Password password) throws BadCipherConfigurationException {

        try {

            final byte[] cipherText = encryptPlainText(plainText, password);
            final String cipherTextEncoded = EncodingUtils.base64Encode(cipherText);
            return new CipherText(cipherTextEncoded);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e);
        }
    }

    /**
     * Decrypts the given cipher text using the specified password.
     *
     * @param cipherText The cipher text to decrypt.
     * @param password The password used to decrypt the cipher text.
     * @return The decrypted plain text.
     * @throws BadCipherTextException If the cipher text is invalid.
     * @throws BadCipherConfigurationException If there is an error in the cipher configuration.
     */
    public PlainText decrypt(CipherText cipherText, Password password) throws BadCipherTextException, BadCipherConfigurationException {
        try {
            final byte[] bytes = decryptCipherText(cipherText, password);
            return new PlainText(new String(bytes));
        } catch (BufferUnderflowException e) {
            throw new BadCipherTextException("Please provide valid cipher text");
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e);
        }

    }

    /**
     * Generates the cipher text from the given plain text and password.
     *
     * @param plainText The plain text to be encrypted.
     * @param password  The password used for encryption.
     * @return The cipher text generated from the plain text and password.
     */
    private byte[] encryptPlainText(PlainText plainText, Password password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] salt = AesCipherUtils.getRandomNonce(SALT_LENGTH_BYTE);
        byte[] iv = AesCipherUtils.getRandomNonce(getAlgorithm().getIvLength());

        Charset encoding = StandardCharsets.UTF_8;
        int encryptionMode = Cipher.ENCRYPT_MODE;

        Cipher cipher = createCipher(password, salt, iv, encryptionMode);
        byte[] cText = cipher.doFinal(plainText.getValue().getBytes(encoding));

        return ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
    }

    /**
     * Retrieves the plain text from the given cipher text using the provided password.
     *
     * @param cipherText The cipher text to decrypt.
     * @param password   The password used for decryption.
     * @return The plain text bytes.
     */
    private byte[] decryptCipherText(CipherText cipherText, Password password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        final String cipherTextEncoded = cipherText.getValue();
        final byte[] cipherTextBytes = EncodingUtils.base64Decode(cipherTextEncoded);

        ByteBuffer buffer = ByteBuffer.wrap(cipherTextBytes); // IV+SALT+CIPHERTEXT

        // 12 bytes GCM vs 16 bytes CTR
        int ivLengthByte = getAlgorithm().getIvLength();
        byte[] iv = new byte[ivLengthByte];
        buffer.get(iv);

        // 16 bytes salt
        byte[] salt = new byte[SALT_LENGTH_BYTE];
        buffer.get(salt);

        byte[] cText = new byte[buffer.remaining()];
        buffer.get(cText);

        Cipher cipher = createCipher(password, salt, iv, Cipher.DECRYPT_MODE);
        return cipher.doFinal(cText);
    }




    private Cipher createCipher(Password password, byte[] salt, byte[] iv, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Key key = AesCipherUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, getKeyLength());
        Cipher cipher = Cipher.getInstance(getAlgorithm().getAlgorithm());
        cipher.init(mode, key, getAlgorithm().getAlgorithmParameterSpec(iv));
        return cipher;
    }


    public static Builder withPassword(Password password) {
        Objects.requireNonNull(password);
        Validate.notBlank(password.getValue());
        return new Builder(password);
    }

    public static Builder withPassword(String password) {
        Validate.notBlank(password);
        return new Builder(password);
    }

    /**
     * The Builder class is used to construct instances of the Encryption class.
     * It provides a convenient way to set the encryption algorithm and key strength, and
     * allows for easy encryption f plain text and decryption of ciphered text.
     */
    public static class Builder {
        private final Password password;

        private EncryptionMode algorithm;
        private EncryptionStrength keyLength;

        public Builder(Password password) {
            Objects.requireNonNull(password);
            Validate.notBlank(password.getValue());
            this.password = password;
        }

        public Builder(String password) {
            Validate.notBlank(password);
            this.password = new Password(password);
        }

        public Builder withMode(EncryptionMode algorithm) {
            Objects.requireNonNull(algorithm);
            this.algorithm = algorithm;
            return this;
        }

        public Builder withStrength(EncryptionStrength encryptionStrength) {
            Objects.requireNonNull(encryptionStrength);
            this.keyLength = encryptionStrength;
            return this;
        }

        public String encrypt(String plainText) throws Exception {
            return encrypt(new PlainText(plainText)).getValue();
        }

        public CipherText encrypt(PlainText plainText) throws BadCipherConfigurationException {
            Objects.requireNonNull(plainText);
            Validate.notBlank(plainText.getValue());
            AesCipher aesCipher = createAesCipher();
            return aesCipher.encrypt(plainText, password);
        }

        public String decrypt(String cipherText) throws BadCipherConfigurationException, BadCipherTextException {
            Validate.notBlank(cipherText);
            return decrypt(new CipherText(cipherText)).getValue();
        }

        public PlainText decrypt(CipherText cipherText) throws BadCipherConfigurationException, BadCipherTextException {
            Objects.requireNonNull(cipherText);
            Validate.notBlank(cipherText.getValue());
            AesCipher aesCipher = createAesCipher();
            return aesCipher.decrypt(cipherText, password);
        }

        private AesCipher createAesCipher() {
            AesCipher aesCipher = new AesCipher();
            if (algorithm != null) {
                aesCipher.setAlgorithm(algorithm);
            }
            if (keyLength != null) {
                aesCipher.setKeyLength(keyLength);
            }
            return aesCipher;
        }
    }

    public synchronized void setAlgorithm(EncryptionMode algorithm) {
        this.algorithm = algorithm;
    }

    public synchronized void setKeyLength(EncryptionStrength keyLength) {
        this.keyLength = keyLength;
    }
}
