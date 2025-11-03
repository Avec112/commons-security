package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.*;
import io.github.avec112.security.crypto.random.RandomUtil;
import io.github.avec112.security.crypto.validate.Validate;
import io.github.avec112.security.encoding.EncodingUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * RsaCipher is a class that provides methods for encrypting and decrypting texts using the RSA encryption algorithm.
 * It extends the BouncyCastleProviderInitializer class, which initializes the BouncyCastle security provider if it is
 * not already initialized.
 * RSA = Rivest-Shamir-Adleman
 * RSA encryption is a type of asymmetric encryption, which uses two different but linked keys. In RSA cryptography,
 * both the public and the private keys can encrypt a message. The opposite key from the one used to encrypt a message
 * is used to decrypt it.
 */
public class RsaCipher extends BouncyCastleProviderInitializer {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Encrypts the provided plain text using the given public key.
     *
     * @param plainText  the plain text to be encrypted
     * @param publicKey  the public key used for encryption
     * @return the encrypted cipher text
     * @throws BadCipherConfigurationException if the RSA cipher cannot be initialized properly
     */
    public CipherText encrypt(PlainText plainText, PublicKey publicKey)
            throws BadCipherConfigurationException {

        Validate.nonNull(plainText, MissingPlainTextException::new);
        Validate.nonBlank(plainText.getValue(), BlankPlainTextException::new);
        Validate.nonNull(publicKey, MissingPublicKeyException::new);

        try {
            byte[] input = plainText.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] cipherText = processCipher(Cipher.ENCRYPT_MODE, publicKey, input);
            return new CipherText(EncodingUtil.base64Encode(cipherText));
        } catch (Exception e) {
            throw new BadCipherConfigurationException(ExceptionUtils.getRootCauseMessage(e), e);
        }
    }

    /**
     * Decrypts the given cipher text using the provided private key.
     *
     * @param cipherText  the cipher text to be decrypted
     * @param privateKey  the private key to be used for decryption
     * @return the decrypted plain text
     * @throws BadCipherConfigurationException if the cipher cannot be configured properly
     * @throws BadCipherTextException if the cipher text is corrupted or invalid
     */
    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey)
            throws BadCipherConfigurationException, BadCipherTextException {

        Validate.nonNull(cipherText, MissingCipherTextException::new);
        Validate.nonBlank(cipherText.getValue(), BlankCipherTextException::new);
        Validate.nonNull(privateKey, MissingPrivateKeyException::new);

        try {
            byte[] decoded = EncodingUtil.base64Decode(cipherText.getValue());
            byte[] decrypted = processCipher(Cipher.DECRYPT_MODE, privateKey, decoded);

            String plain = new String(decrypted, StandardCharsets.UTF_8);
            validateDecryptedOutput(plain);

            return new PlainText(plain);

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            // Typical symptom of corrupt ciphertext or wrong key
            throw new BadCipherTextException("Decryption failed due to corrupt cipher text or wrong key");
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new BadCipherConfigurationException("RSA cipher configuration failed", e);
        }
    }

    /**
     * Simple sanity check to detect corrupted or meaningless decrypted data.
     *
     * @param plain the decrypted text as UTF-8
     * @throws BadCipherTextException if the output is empty, unreadable, or otherwise invalid
     */
    private void validateDecryptedOutput(String plain) throws BadCipherTextException {
        if (StringUtils.isBlank(plain) || plain.length() < 2 ||
                !plain.matches("[\\p{Print}\\p{Space}]+")) {
            throw new BadCipherTextException("Decrypted data appears invalid or produced using wrong key");
        }
    }

    /**
     * Gets the cipher text by performing encryption or decryption using the specified cipher mode and key.
     *
     * @param cipherMode the cipher mode to use: Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key the key used for encryption or decryption
     * @param input the input byte array to process
     * @return the output cipher text byte array
     * @throws NoSuchPaddingException if the cipher padding scheme is invalid
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeyException if the key is invalid
     * @throws IllegalBlockSizeException if the data block is invalid
     * @throws BadPaddingException if padding is incorrect (often indicates wrong key)
     */
    private byte[] processCipher(int cipherMode, Key key, byte[] input)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Validate.nonNull(key, MissingKeyException::new);
        Cipher cipher = initiateCipher(cipherMode, key);
        return cipher.doFinal(input);
    }

    /**
     * Initializes a Cipher object with the specified encryption mode and key.
     *
     * @param encryptMode the encryption mode to use, either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key the key used for encryption or decryption
     * @return the initialized Cipher object
     * @throws NoSuchPaddingException if padding configuration is invalid
     * @throws NoSuchAlgorithmException if RSA algorithm is unavailable
     * @throws InvalidKeyException if key is invalid or unsupported
     */
    private Cipher initiateCipher(int encryptMode, Key key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        Validate.nonNull(key, NullPointerException::new);
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(encryptMode, key, RandomUtil.secureRandom());
        return cipher;
    }
}
