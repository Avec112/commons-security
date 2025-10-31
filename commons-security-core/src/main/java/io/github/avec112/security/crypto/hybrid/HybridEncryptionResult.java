package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * This class represents the result of a Hybrid Encryption operation.
 *
 * <p>Supports JSON serialization and deserialization for storage and transmission.</p>
 */
@Getter
@AllArgsConstructor
public class HybridEncryptionResult {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String VERSION = "1.0";

    private final String version;
    private final CipherText cipherText;
    private final String encryptedKey;
    private final EncryptionMode aesEncryptionMode;
    private final EncryptionStrength aesEncryptionStrength;

    /**
     * Creates a new HybridEncryptionResult with the current version.
     */
    public HybridEncryptionResult(CipherText cipherText, String encryptedKey,
                                  EncryptionMode aesEncryptionMode, EncryptionStrength aesEncryptionStrength) {
        this(VERSION, cipherText, encryptedKey, aesEncryptionMode, aesEncryptionStrength);
    }

    /**
     * Serializes this object to JSON format.
     *
     * @return JSON string representation
     */
    public String toJson() {
        return GSON.toJson(this);
    }

    /**
     * Deserializes a HybridEncryptionResult from JSON format.
     *
     * @param json the JSON string to parse
     * @return the deserialized HybridEncryptionResult
     * @throws com.google.gson.JsonSyntaxException if JSON is malformed
     */
    public static HybridEncryptionResult fromJson(String json) {
        return GSON.fromJson(json, HybridEncryptionResult.class);
    }

    /**
     * Returns a human-readable description of the AES encryption configuration.
     *
     * @return a string in the format "MODE@STRENGTH-bit" (e.g., "GCM@256-bit")
     */
    public String describe() {
        return String.format("%s@%d-bit", aesEncryptionMode, aesEncryptionStrength.getLength());
    }
}
