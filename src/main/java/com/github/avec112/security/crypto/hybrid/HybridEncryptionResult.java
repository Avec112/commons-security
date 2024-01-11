package com.github.avec112.security.crypto.hybrid;

import com.github.avec112.security.crypto.aes.EncryptionMode;
import com.github.avec112.security.crypto.aes.EncryptionStrength;
import lombok.Value;

@Value
public class HybridEncryptionResult {
    String cipherText;
    String encryptedSymmetricalKey;
    EncryptionMode aesEncryptionMode;
    EncryptionStrength aesEncryptionStrength;
}
