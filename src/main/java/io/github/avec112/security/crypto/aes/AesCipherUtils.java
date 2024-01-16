package io.github.avec112.security.crypto.aes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;



/**
 * This class provides utility methods for AES cipher encryption and decryption.
 */
public class AesCipherUtils {
    private AesCipherUtils() {
    }



    /**
     * Generates a random nonce of the specified number of bytes.
     *
     * @param numBytes The number of bytes for the nonce.
     * @return A byte array representing the random nonce.
     */
    public static byte[] getRandomNonce(int numBytes) {
        byte [] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
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
    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt, EncryptionStrength keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // PBE = Password-based Encryption
        KeySpec spec = new PBEKeySpec(password, salt, 65536, keyLength.getLength());
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }


    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param bytes The byte array to be converted.
     * @return The hexadecimal string representation of the byte array.
     */
    public static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Converts a byte array to a hexadecimal string representation with a specified block size.
     * Each block of the specified size will be separated by a space.
     *
     * @param bytes The byte array to be converted.
     * @param blockSize The size of each block in terms of bytes.
     * @return The hexadecimal string representation of the byte array with block size separation.
     */
    @SuppressWarnings("unused")
    public static String hexWithBlockSize(byte [] bytes, int blockSize) {
        String hex = hex(bytes);

        // one hex = 2 chars
        blockSize = blockSize * 2;

        List<String> result = new ArrayList<>();
        int index = 0;
        while(index < hex.length()) {
            result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
            index += blockSize;
        }
        return result.toString();
    }

}