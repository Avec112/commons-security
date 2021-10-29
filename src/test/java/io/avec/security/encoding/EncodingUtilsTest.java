package io.avec.security.encoding;

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
    void encode(String input, String expected) {
        byte [] src = input.getBytes();
        assertEquals(expected, EncodingUtils.base64Encode(src));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void decode(String expected, String input) {
        final String actual = new String(EncodingUtils.base64Decode(input));
        assertEquals(expected, actual);
    }
}