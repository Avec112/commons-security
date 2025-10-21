package com.github.avec112.security.crypto.aes;

import lombok.Getter;
import org.apache.commons.lang3.NotImplementedException;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;


/**
 * Enumeration of encryption modes for AES encryption.
 */
@Getter
public enum EncryptionMode {
    GCM ("AES/GCM/NoPadding", 12), // iv length 12 is recommended by NIST for GCM
    CTR ("AES/CTR/NoPadding", 16);
    // Oracle Java official stance is that AES/CTR/PKCS5Padding is not supported
    // fails on Linux with NoSuchAlgorithmException but not on Windows for some reason
//    CTR("AES/CTR/PKCS5Padding", 16);

    private final String algorithm;
    private final int ivLength;

    EncryptionMode(String algorithm, int ivLength) {
        this.algorithm = algorithm;
        this.ivLength = ivLength;
    }

    /**
     * Retrieves the AlgorithmParameterSpec for the specified IV based on the encryption mode.
     *
     * @param iv The initialization vector (IV) used for encryption or decryption.
     * @return The AlgorithmParameterSpec object for the specified IV.
     * @throws NotImplementedException if the encryption mode is not implemented.
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec(byte [] iv) {
        if(this.equals(GCM)) {
            int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
            return new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        } else if(this.equals(CTR)) {
            return new IvParameterSpec(iv);
        }
        throw new NotImplementedException(this.name() + " is not implemented.");
    }
}
