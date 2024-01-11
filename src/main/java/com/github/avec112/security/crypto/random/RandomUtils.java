package com.github.avec112.security.crypto.random;


import com.github.avec112.security.encoding.EncodingUtils;

import java.security.SecureRandom;

public class RandomUtils {

    private RandomUtils() {
    }

    /**
     * Populates array with random bytes using SecureRandom
     * @param size length of byte array
     * @return random bytes
     */
    public static byte[] randomBytes(int size) {
        byte[] values = new byte[size];
        new SecureRandom().nextBytes(values);
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

}
