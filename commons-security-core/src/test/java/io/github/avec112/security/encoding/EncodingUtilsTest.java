package io.github.avec112.security.encoding;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncodingUtilsTest {

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void base64Encode(String input, String expected) {
        byte [] src = input.getBytes(StandardCharsets.UTF_8);
        assertEquals(expected, EncodingUtils.base64Encode(src));
    }

    @Test
    void base64EncodeBadInput() {
        // null
        assertThrows(NullPointerException.class, () ->
                EncodingUtils.base64Encode(null));
        // blank
        byte[] bytes = "".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () ->
                EncodingUtils.base64Encode(bytes));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void base64Decode(String expected, String input) {
        final String actual = new String(EncodingUtils.base64Decode(input), StandardCharsets.UTF_8);
        assertEquals(expected, actual);
    }


    @ParameterizedTest
    @CsvSource({
            "Hello!, 48656c6c6f21",
            "æøåö, c3a6c3b8c3a5c3b6",
            "1234!#&, 31323334212326"
    })
    void hexEncode(String input, String expected) {
        byte [] src = input.getBytes(StandardCharsets.UTF_8);
        assertEquals(expected, EncodingUtils.hexEncode(src));
    }

    @Test
    void hexEncodeBadInput() {
        // null
        assertThrows(NullPointerException.class, () ->
                EncodingUtils.hexEncode(null));
        // blank
        byte[] bytes = "".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () ->
                EncodingUtils.hexEncode(bytes));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, 48656c6c6f21",
            "æøåö, c3a6c3b8c3a5c3b6",
            "1234!#&, 31323334212326"
    })
    void hexDecode(String expected, String input) throws DecoderException {
        final String actual = new String(EncodingUtils.hexDecode(input), StandardCharsets.UTF_8);
        assertEquals(expected, actual);
    }
}