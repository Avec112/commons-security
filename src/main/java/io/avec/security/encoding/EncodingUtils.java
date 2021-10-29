package io.avec.security.encoding;

import org.apache.commons.lang3.Validate;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

public class EncodingUtils {

    public static String base64Encode(byte [] src) {
        Validate.notNull(src);
        Validate.isTrue(src.length > 0);

        return getEncoder().encodeToString(src);
    }

    public static byte[] base64Decode(String src) {
        Validate.notBlank(src);
        return getDecoder().decode(src);
    }
}
