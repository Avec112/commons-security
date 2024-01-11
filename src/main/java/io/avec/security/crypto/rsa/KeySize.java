package io.avec.security.crypto.rsa;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum KeySize {
    BIT_1024(1024),
    BIT_2048(2048),
    BIT_3072(3072),
    BIT_4096(4096);
    private final int keySize;

    public static KeySize getKeySize(int keySize) {
        if(keySize == BIT_1024.keySize) {
            return BIT_1024;
        } else if(keySize == BIT_2048.keySize) {
            return BIT_2048;
        } else if(keySize == BIT_3072.keySize) {
            return BIT_3072;
        } else if(keySize == BIT_4096.keySize) {
            return BIT_4096;
        }
        throw new IllegalArgumentException("keySize " + keySize + " not supported.");
    }
}
