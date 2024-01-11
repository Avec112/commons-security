package io.avec.security.crypto.hybrid;

import io.avec.security.crypto.aes.EncryptionMode;
import io.avec.security.crypto.aes.EncryptionStrength;
import lombok.Value;

@Value
public class HybridEncryptionResult {
    String cipherText;
    String encryptedSymmetricalKey;
    EncryptionMode aesEncryptionMode;
    EncryptionStrength aesEncryptionStrength;
}
