package com.github.avec112.security.encoding;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Validate;

import java.util.Objects;

public class EncodingUtils {

    public static String base64Encode(byte [] src) {
        Objects.requireNonNull(src, "Argument src cannot be null");
        Validate.isTrue(src.length > 0);

        return Base64.encodeBase64String(src);
    }

    public static byte[] base64Decode(String src) {
        Validate.notBlank(src, "Argument src cannot be null or blank");
        return Base64.decodeBase64(src);
    }

    public static String hexEncode(byte [] src) {
        Objects.requireNonNull(src, "Argument src cannot be null");
        Validate.isTrue(src.length > 0);

        return Hex.encodeHexString(src);
    }

    public static byte[] hexDecode(String src) throws DecoderException {
        Validate.notBlank(src, "Argument src cannot be null or blank");
        return Hex.decodeHex(src);
    }

}
