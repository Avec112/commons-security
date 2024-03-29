package io.github.avec112.security.crypto.digest;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.encoding.EncodingUtils;
import org.apache.commons.lang3.Validate;

import java.security.MessageDigest;
import java.util.Objects;

/**
 * This class might use algorithms from BouncyCastle so BouncyCastleProvider is added statically
 */
public class DigestUtils extends BouncyCastleProviderInitializer {

    private DigestUtils() {}

    /**
     * Create SHA-256 digest
     * @param data content to digest
     * @return SHA-256 digest as byte array
     * @throws Exception if an error happens
     */
    public static byte[] digest(String data) throws Exception {
        Validate.notBlank(data);
        MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA_256.getAlgorithm(), "BC");

        return digest.digest(data.getBytes());
    }

    /**
     * Create a digest
     * @param data content to digest
     * @param digestAlgorithm the hashing to use
     * @return digest as byte array
     * @throws Exception if an error happens
     */
    public static byte[] digest(String data, DigestAlgorithm digestAlgorithm) throws Exception {
        Validate.notBlank(data);
        Objects.requireNonNull(digestAlgorithm);

        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getAlgorithm(), "BC");
        return digest.digest(data.getBytes());
    }

    /**
     * Create SHA-256 digest encoded with Base64
     * @param data content to digest
     * @return SHA-256 digest as byte array encoded with Base64
     * @throws Exception if an error happens
     */
    public static String base64Digest(String data) throws Exception {
        byte[] digest = digest(data);
        return EncodingUtils.base64Encode(digest);
    }

    /**
     * Create SHA-256 digest encoded with Hex
     * @param data content to digest
     * @return SHA-256 digest as byte array encoded with Hex
     * @throws Exception if an error happens
     */
    public static String hexDigest(String data) throws Exception {
        byte[] digest = digest(data);
        return EncodingUtils.base64Encode(digest);
    }
}
