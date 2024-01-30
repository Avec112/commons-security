package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import lombok.Value;

@Value
public class HybridEncryptionResult {
    CipherText cipherText;
    String encryptedSymmetricalKey;
    EncryptionMode aesEncryptionMode;
    EncryptionStrength aesEncryptionStrength;
}
