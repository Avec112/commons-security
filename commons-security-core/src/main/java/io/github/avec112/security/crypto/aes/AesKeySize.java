package io.github.avec112.security.crypto.aes;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.stream.Stream;

/**
 * Enum representing predefined key sizes for AES symmetric encryption.
 *
 * The {@code AesKeySize} enum provides constants for the three standard AES key sizes:
 * 128-bit, 192-bit, and 256-bit. These can be used when generating AES keys.
 */
@RequiredArgsConstructor
@Getter
public enum AesKeySize {
    BIT_128(128),
    BIT_192(192),
    BIT_256(256);

    private final int keySize;

    /**
     * Retrieves the {@code AesKeySize} enumeration constant corresponding to the specified key size.
     *
     * @param keySize the key size value represented as an integer (128, 192, or 256).
     * @return the {@link AesKeySize} constant that matches the specified key size.
     * @throws IllegalArgumentException if the specified key size is not supported by AES.
     */
    public static AesKeySize getKeySize(int keySize) {
        return Stream.of(AesKeySize.values())
                .filter(k -> k.keySize == keySize)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("AES keySize " + keySize + " not supported. Valid sizes: 128, 192, 256"));
    }
}
