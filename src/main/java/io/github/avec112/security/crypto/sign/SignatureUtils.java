package io.github.avec112.security.crypto.sign;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/**
 * Utility class for creating and verifying RSA signatures using RSASSA-PSS.
 *
 * <p>This implementation uses SHA-256 as the message digest and MGF1 with SHA-256
 * as the mask generation function, following current best practices.</p>
 *
 * <p>The resulting signatures are probabilistic, meaning that signing the same data
 * twice with the same key will produce different results. Verification is deterministic.</p>
 */
public class SignatureUtils extends BouncyCastleProviderInitializer {

    private static final String ALGORITHM = "RSASSA-PSS";

    // Recommended parameters for SHA-256 PSS
    private static final PSSParameterSpec PSS_SHA256_PARAMS = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,  // salt length in bytes
            1    // trailer field (always 1)
    );

    private SignatureUtils() {
    }


    /**
     * Signs the given text using RSASSA-PSS (SHA-256 + MGF1).
     *
     * @param data       the string to sign
     * @param privateKey the private key
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Validate.notBlank(data, "data cannot be blank");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        return sign(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Signs the given byte array using RSASSA-PSS (SHA-256 + MGF1).
     *
     * @param data       the data to sign
     * @param privateKey the private key
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] sign(byte [] data, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        Signature signature = Signature.getInstance(ALGORITHM);
        signature.setParameter(PSS_SHA256_PARAMS);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies a signature for the given text using RSASSA-PSS (SHA-256 + MGF1).
     *
     * @param signatureBytes the signature to verify
     * @param data           the original string
     * @param publicKey      the corresponding public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     */
    public static boolean verify(byte[] signatureBytes, String data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes);
        Validate.notBlank(data);
        Objects.requireNonNull(publicKey);

        return verify(signatureBytes, data.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    /**
     * Verifies a signature for the given byte array using RSASSA-PSS (SHA-256 + MGF1).
     *
     * @param signatureBytes the signature to verify
     * @param data           the original data
     * @param publicKey      the corresponding public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     */
    public static boolean verify(byte[] signatureBytes, byte[] data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes);
        Objects.requireNonNull(data);
        Objects.requireNonNull(publicKey);

        Signature signature = Signature.getInstance(ALGORITHM);
        signature.setParameter(PSS_SHA256_PARAMS);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
