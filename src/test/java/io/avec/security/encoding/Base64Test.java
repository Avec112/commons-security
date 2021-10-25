package io.avec.security.encoding;

import io.avec.security.encoding.Base64;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Base64Test {

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void encode(String input, String expected) {
        byte [] src = input.getBytes();
        assertEquals(expected, Base64.encode(src));
    }

    @ParameterizedTest
    @CsvSource({
            "Hello!, SGVsbG8h",
            "æøåö, w6bDuMOlw7Y=",
            "1234!#&, MTIzNCEjJg=="
    })
    void decode(String expected, String input) {
        final String actual = new String(Base64.decode(input));
        assertEquals(expected, actual);
    }
}