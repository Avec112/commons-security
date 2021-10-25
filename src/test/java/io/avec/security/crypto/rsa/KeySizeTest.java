package io.avec.security.crypto.rsa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeySizeTest {

    @Test
    void getKeySize() {
        assertEquals(1024, KeySize.BIT_1024.getKeySize());
        assertEquals(2048, KeySize.BIT_2048.getKeySize());
        assertEquals(4096, KeySize.BIT_4096.getKeySize());
    }
}