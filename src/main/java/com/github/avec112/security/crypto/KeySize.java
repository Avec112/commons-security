package com.github.avec112.security.crypto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.stream.Stream;

/**
 * Enum representing predefined key sizes for cryptographic operations.
 *
 * The {@code KeySize} enum provides a set of constants for commonly used key sizes in bits,
 * such as 2048, 3072, and 4096. These constants can be used to define the key size
 * in RSA key pair generation or other cryptographic contexts.
 */
@RequiredArgsConstructor
@Getter
public enum KeySize {
    BIT_2048(2048),
    BIT_3072(3072),
    BIT_4096(4096);
    private final int keySize;

    /**
     * Retrieves the {@code KeySize} enumeration constant corresponding to the specified key size.
     * The method checks the predefined key sizes in the {@link KeySize} enum and returns the matching constant.
     * If no match is found, an {@link IllegalArgumentException} is thrown.
     *
     * @param keySize the key size value represented as an integer (e.g., 2048, 3072, 4096).
     * @return the {@link KeySize} constant that matches the specified key size.
     * @throws IllegalArgumentException if the specified key size is not supported.
     */
    public static KeySize getKeySize(int keySize) {
        return Stream.of(KeySize.values())
                .filter(k -> k.keySize == keySize)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("keySize " + keySize + " not supported."));
    }
}
