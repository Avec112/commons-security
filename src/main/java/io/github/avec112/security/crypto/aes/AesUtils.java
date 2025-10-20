package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.random.RandomUtils;
import io.github.avec112.security.encoding.EncodingUtils;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;



/**
 * This class provides utility methods for AES encryption and decryption.
 * AES = Advanced Encryption Standard.
 * AES uses the same key for encryption also called symmetrical encryption.
 */
public class AesUtils extends BouncyCastleProviderInitializer {

    private AesUtils() {
    }

    /**
     * Generates a random nonce of the specified number of bytes.
     *
     * @param numBytes The number of bytes for the nonce.
     * @return A byte array representing the random nonce.
     */
    public static byte[] getRandomNonce(int numBytes) {
        byte [] nonce = new byte[numBytes];
        RandomUtils.secureRandom().nextBytes(nonce);
        return nonce;
    }


    /**
     * Generates an AES key of the specified key size.
     *
     * @param keySize The size of the AES key in bits.
     * @return The generated AES key.
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     */
    public static SecretKey getAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    /**
     * Retrieves an AES secret key derived from a password using PBKDF2 algorithm.
     *
     * @param password The password from which the AES key is derived.
     * @param salt The salt used for key derivation.
     * @param keyLength The desired key length.
     * @return The generated AES secret key.
     */
    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // PBE = Password-based Encryption
        KeySpec spec = new PBEKeySpec(password, salt, 65536, keyLength);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * Creates a Cipher object for encryption or decryption using the specified parameters.
     *
     * @param password          The password from which the AES key is derived.
     * @param salt              The salt used for key derivation.
     * @param iv                The initialization vector (IV) used for encryption or decryption.
     * @param mode              The mode of operation for the cipher: Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE.
     * @param encryptionMode    The encryption mode to be used. See {@link EncryptionMode} for available modes.
     * @param keyLength         The desired length of the AES key.
     * @return The created Cipher object.

     */
    public static Cipher createCipher(Password password, byte[] salt, byte[] iv, int mode, EncryptionMode encryptionMode, int keyLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Key key = AesUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, keyLength);
        Cipher cipher = Cipher.getInstance(encryptionMode.getAlgorithm());
        cipher.init(mode, key, encryptionMode.getAlgorithmParameterSpec(iv));
        return cipher;
    }

    /**
     * Generates a Base64-encoded random key sized according to the given AES encryption strength.
     *
     * @param strength the desired AES key strength (128, 192, or 256 bits)
     * @return Base64-encoded random key
     */
    public static String generateBase64Key(EncryptionStrength strength) {
        int keyBytes = strength.getLength() / 8;
        byte[] key = RandomUtils.randomBytes(keyBytes);
        return EncodingUtils.base64Encode(key);
    }

}
