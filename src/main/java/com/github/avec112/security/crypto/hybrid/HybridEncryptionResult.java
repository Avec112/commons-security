package com.github.avec112.security.crypto.hybrid;

import com.github.avec112.security.crypto.aes.EncryptionMode;
import com.github.avec112.security.crypto.aes.EncryptionStrength;
import com.github.avec112.security.crypto.domain.CipherText;
import lombok.Value;

/**
 * This class represents the result of a Hybrid Encryption operation.
 */
@Value
public class HybridEncryptionResult {
    CipherText cipherText;
    String encryptedSymmetricalKey;
    EncryptionMode aesEncryptionMode;
    EncryptionStrength aesEncryptionStrength;
}
