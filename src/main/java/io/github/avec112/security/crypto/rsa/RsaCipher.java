package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.encoding.EncodingUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * The RsaCipher class provides methods for encrypting and decrypting data using RSA encryption algorithm.
 * It extends the BouncyCastleProviderInitializer class to initialize the Bouncy Castle provider.
 */
public class RsaCipher extends BouncyCastleProviderInitializer {
    public static final String RSA_CIPHER = "RSA";
    public static final String CIPHER_PROVIDER = "BC";

    /**
     * Encrypts a PlainText using the provided PublicKey.
     *
     * @param plainText   the PlainText to encrypt
     * @param publicKey   the PublicKey to use for encryption
     * @return the encrypted CipherText
     * @throws Exception if encryption fails
     */
    public CipherText encrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        byte[] cipherText = getCipherText(Cipher.ENCRYPT_MODE, publicKey, plainText.getValue().getBytes(StandardCharsets.UTF_8));
        return new CipherText(EncodingUtils.base64Encode(cipherText));
    }

    /**
     *
     */
    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey) throws BadCipherConfigurationException {
        try {
            byte[] plainTextBytes = getCipherText(Cipher.DECRYPT_MODE, privateKey, EncodingUtils.base64Decode(cipherText.getValue()));
            return new PlainText(new String(plainTextBytes));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new BadCipherConfigurationException(ExceptionUtils.getRootCause(e));
        }

    }

    private byte[] getCipherText(int cipherMode, Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final Cipher cipher = initiateCipher(cipherMode, key);
        return cipher.doFinal(input);
    }

    private Cipher initiateCipher(int encryptMode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER, CIPHER_PROVIDER);
        cipher.init(encryptMode, key);
        return cipher;
    }
}
