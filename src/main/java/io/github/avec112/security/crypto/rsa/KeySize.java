package io.github.avec112.security.crypto.rsa;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.stream.Stream;

@RequiredArgsConstructor
@Getter
public enum KeySize {
    BIT_1024(1024),
    BIT_2048(2048),
    BIT_3072(3072),
    BIT_4096(4096);
    private final int keySize;

    public static KeySize getKeySize(int keySize) {
        return Stream.of(KeySize.values())
                .filter(k -> k.keySize == keySize)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("keySize " + keySize + " not supported."));
    }
}
