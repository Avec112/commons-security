package io.avec.security.encoding;

import org.apache.commons.lang3.Validate;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

public class Base64 {

    public static String encode(byte [] src) {
        Validate.notNull(src);
        Validate.isTrue(src.length > 0);

        return getEncoder().encodeToString(src);
    }

    public static byte[] decode(String src) {
        Validate.notBlank(src);
        return getDecoder().decode(src);
    }
}
