package com.github.avec112.security.crypto.aes;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * This enum represents the encryption strength for AES encryption.
 */
@Slf4j
@Getter
public enum EncryptionStrength {
    BIT_128(128),
    BIT_192(192),
    BIT_256(256);

    private final int length;

    EncryptionStrength(int length) {
        this.length = length;
    }

    /**
     * Returns the {@link EncryptionStrength} enum value associated with the specified encryption strength.
     *
     * @param encryptionStrength the encryption strength in bits
     * @return the {@link EncryptionStrength} enum value associated with the specified encryption strength
     */
    public static EncryptionStrength getAESKeyLength(int encryptionStrength) {
        switch (encryptionStrength) {
            case 128:
                return EncryptionStrength.BIT_128;
            case 192:
                return EncryptionStrength.BIT_192;
            case 256:
                return EncryptionStrength.BIT_256;
            default:
                log.warn("encryptionStrength={} not supported. Defaulting to 256 bit", encryptionStrength);
                return EncryptionStrength.BIT_256;
        }
    }
}
