package io.avec.security.encoding;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Validate;

public class EncodingUtils {

    public static String base64Encode(byte [] src) {
        Validate.notNull(src);
        Validate.isTrue(src.length > 0);

        return Base64.encodeBase64String(src);
    }

    public static byte[] base64Decode(String src) {
        Validate.notBlank(src);
        return Base64.decodeBase64(src);
    }

    public static String hexEncode(byte [] src) {
        Validate.notNull(src);
        Validate.isTrue(src.length > 0);

        return Hex.encodeHexString(src);
    }

    public static byte[] hexDecode(String src) throws DecoderException {
        Validate.notBlank(src);
        return Hex.decodeHex(src);
    }

}
