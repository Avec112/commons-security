package io.github.avec112.security.crypto.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AesKeySizeTest {

    @Test
    void getKeySize() {
        assertEquals(128, AesKeySize.BIT_128.getKeySize());
        assertEquals(192, AesKeySize.BIT_192.getKeySize());
        assertEquals(256, AesKeySize.BIT_256.getKeySize());
    }
}
