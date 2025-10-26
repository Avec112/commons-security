package com.github.avec112.security.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeySizeTest {

    @Test
    void getKeySize() {
        assertEquals(2048, KeySize.BIT_2048.getKeySize());
        assertEquals(3072, KeySize.BIT_3072.getKeySize());
        assertEquals(4096, KeySize.BIT_4096.getKeySize());
    }
}