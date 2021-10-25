package io.avec.crypto.aes;

import lombok.extern.slf4j.Slf4j;

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
 * Created by avec112 on 27.08.2020.
 */
@Slf4j
public class AesCipherUtils {

    private AesCipherUtils() {
    }

    // generate secure byte array
    public static byte[] getRandomNonce(int numBytes) {
        byte [] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // generate secret AES key
    public static SecretKey getAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt, EncryptionStrength keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug("AES key length: {} bits", keyLength.getLength());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // iterationCount = 65536
        KeySpec spec = new PBEKeySpec(password, salt, 65536, keyLength.getLength());
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // print hex with block size split
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
