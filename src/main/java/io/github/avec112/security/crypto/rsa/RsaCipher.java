package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.*;
import io.github.avec112.security.crypto.validate.Validate;
import io.github.avec112.security.encoding.EncodingUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * RsaCipher is a class that provides methods for encrypting and decrypting texts using the RSA encryption algorithm.
 * It extends the BouncyCastleProviderInitializer class, which initializes the BouncyCastle security provider if it is not already initialized.
 */
public class RsaCipher extends BouncyCastleProviderInitializer {
    public static final String RSA_CIPHER = "RSA";
    public static final String CIPHER_PROVIDER = "BC";

    /**
     * Encrypts the provided plain text using the given public key.
     *
     * @param plainText  the plain text to be encrypted
     * @param publicKey  the public key used for encryption
     * @return the encrypted cipher text
     */
    public CipherText encrypt(PlainText plainText, PublicKey publicKey) throws BadCipherConfigurationException {
        Validate.nonNull(plainText, MissingPlainTextException::new);
        Validate.nonBlank(plainText.getValue(), BlankPlainTextException::new);
        Validate.nonNull(publicKey, MissingPublicKeyException::new);

        try {
            byte[] cipherText = getCipherText(Cipher.ENCRYPT_MODE, publicKey, plainText.getValue().getBytes(StandardCharsets.UTF_8));
            return new CipherText(EncodingUtils.base64Encode(cipherText));
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
     */
    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey) throws BadCipherConfigurationException {
        Validate.nonNull(cipherText, MissingCipherTextException::new);
        Validate.nonBlank(cipherText.getValue(), BlankCipherTextException::new);
        Validate.nonNull(privateKey, MissingPrivateKeyException::new);

        try {
            byte[] plainTextBytes = getCipherText(Cipher.DECRYPT_MODE, privateKey, EncodingUtils.base64Decode(cipherText.getValue()));
            return new PlainText(new String(plainTextBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new BadCipherConfigurationException(ExceptionUtils.getRootCauseMessage(e), e);
        }

    }

    /**
     * Gets the cipher text by performing encryption or decryption using the specified cipher mode and key.
     *
     * @param cipherMode the cipher mode to use: Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key the key used for encryption or decryption
     * @param input the input byte array to process
     * @return the output cipher text byte array
     */
    private byte[] getCipherText(int cipherMode, Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Validate.nonNull(key, MissingKeyException::new);
        final Cipher cipher = initiateCipher(cipherMode, key);
        return cipher.doFinal(input);
    }

    /**
     * Initializes a Cipher object with the specified encryption mode and key.
     *
     * @param encryptMode the encryption mode to use, either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key the key used for encryption or decryption
     * @return the initialized Cipher object
     */
    private Cipher initiateCipher(int encryptMode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Validate.nonNull(key, NullPointerException::new);
        Cipher cipher = Cipher.getInstance(RSA_CIPHER, CIPHER_PROVIDER);
        cipher.init(encryptMode, key);
        return cipher;
    }
}
