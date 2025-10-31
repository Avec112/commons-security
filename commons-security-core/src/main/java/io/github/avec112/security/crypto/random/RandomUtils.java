package io.github.avec112.security.crypto.random;


import io.github.avec112.security.encoding.EncodingUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The RandomUtils class provides utility methods for generating random values.
 */
public class RandomUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        SecureRandom tmp;
        try {
            // Prefer the strongest available PRNG (may block briefly on some systems)
            tmp = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // Fallback: standard non-blocking SecureRandom
            tmp = new SecureRandom();
        }
        SECURE_RANDOM = tmp;
    }

    private RandomUtils() {
    }

    /**
     * Populates array with random bytes using SecureRandom
     * @param size length of byte array
     * @return random bytes
     */
    public static byte[] randomBytes(int size) {
        byte[] values = new byte[size];
        SECURE_RANDOM.nextBytes(values);
        return values;
    }

    /**
     * A randomized byte array (See randomBytes(..)) that is hex encoded
     * @param size SecureRandom byte size
     * @return hex encoded random bytes
     */
    public static String randomString(int size) {
        return EncodingUtils.hexEncode(randomBytes(size));
    }

    /**
     * Provides access to the singleton instance of SecureRandom used within the utility class.
     *
     * @return the shared SecureRandom instance for generating secure random values
     */
    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }

}
