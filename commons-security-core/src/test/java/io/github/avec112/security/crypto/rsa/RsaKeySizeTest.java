package io.github.avec112.security.crypto.rsa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RsaKeySizeTest {

    @Test
    void getKeySize() {
        assertEquals(2048, RsaKeySize.BIT_2048.getKeySize());
        assertEquals(3072, RsaKeySize.BIT_3072.getKeySize());
        assertEquals(4096, RsaKeySize.BIT_4096.getKeySize());
    }
}