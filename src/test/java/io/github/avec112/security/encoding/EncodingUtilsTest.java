package io.github.avec112.security.encoding;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncodingUtilsTest {

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void base64Encode(String input, String expected) {
        byte [] src = input.getBytes();
        assertEquals(expected, EncodingUtils.base64Encode(src));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void base64Decode(String expected, String input) {
        final String actual = new String(EncodingUtils.base64Decode(input));
        assertEquals(expected, actual);
    }


    @ParameterizedTest
    @CsvSource({
            "Hello!, 48656c6c6f21",
            "æøåö, c3a6c3b8c3a5c3b6",
            "1234!#&, 31323334212326"
    })
    void hexEncode(String input, String expected) {
        byte [] src = input.getBytes();
        assertEquals(expected, EncodingUtils.hexEncode(src));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, 48656c6c6f21",
            "æøåö, c3a6c3b8c3a5c3b6",
            "1234!#&, 31323334212326"
    })
    void hexDecode(String expected, String input) throws DecoderException {
        final String actual = new String(EncodingUtils.hexDecode(input));
        assertEquals(expected, actual);
    }
}