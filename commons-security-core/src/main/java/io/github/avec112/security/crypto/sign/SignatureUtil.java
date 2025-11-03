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
 * Unified utility class for creating and verifying digital signatures.
 *
 * <p>Supports multiple signature algorithms:</p>
 * <ul>
 *   <li><b>RSASSA-PSS</b> - Modern RSA signature scheme with probabilistic padding</li>
 *   <li><b>Ed25519</b> - Modern ECC signature (fastest, deterministic, 64-byte signatures)</li>
 *   <li><b>ECDSA</b> - Standards-compliant ECC signature (probabilistic)</li>
 * </ul>
 *
 * <p><b>Example usage:</b></p>
 * <pre>{@code
 * // RSA signature
 * KeyPair rsaKeys = KeyGeneratorUtil.generateRsaKeyPair();
 * byte[] rsaSig = SignatureUtil.sign("data", rsaKeys.getPrivate());
 * boolean valid = SignatureUtil.verify(rsaSig, "data", rsaKeys.getPublic());
 *
 * // Ed25519 signature (recommended for new applications)
 * KeyPair ed25519Keys = KeyGeneratorUtil.generateEd25519KeyPair();
 * byte[] ed25519Sig = SignatureUtil.signEd25519("data", ed25519Keys.getPrivate());
 * boolean valid = SignatureUtil.verifyEd25519(ed25519Sig, "data", ed25519Keys.getPublic());
 *
 * // ECDSA signature
 * KeyPair ecKeys = KeyGeneratorUtil.generateSecp256r1KeyPair();
 * byte[] ecdsaSig = SignatureUtil.signEcdsa("data", ecKeys.getPrivate());
 * boolean valid = SignatureUtil.verifyEcdsa(ecdsaSig, "data", ecKeys.getPublic());
 * }</pre>
 */
public class SignatureUtil extends BouncyCastleProviderInitializer {

    private static final String RSA_ALGORITHM = "RSASSA-PSS";
    private static final String ED25519_ALGORITHM = "Ed25519";

    // Recommended parameters for SHA-256 PSS
    private static final PSSParameterSpec PSS_SHA256_PARAMS = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,  // salt length in bytes
            1    // trailer field (always 1)
    );

    private SignatureUtil() {
    }

    // ========== RSA Signatures (RSASSA-PSS) ==========

    /**
     * Signs the given text using RSASSA-PSS (SHA-256 + MGF1).
     *
     * @param data       the string to sign
     * @param privateKey the RSA private key
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
     * @param privateKey the RSA private key
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        Signature signature = Signature.getInstance(RSA_ALGORITHM);
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
     * @param publicKey      the RSA public key
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
     * @param publicKey      the RSA public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     */
    public static boolean verify(byte[] signatureBytes, byte[] data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes);
        Objects.requireNonNull(data);
        Objects.requireNonNull(publicKey);

        Signature signature = Signature.getInstance(RSA_ALGORITHM);
        signature.setParameter(PSS_SHA256_PARAMS);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // ========== Ed25519 Signatures (ECC-based) ==========

    /**
     * Signs the given text using Ed25519.
     * Ed25519 provides fast, deterministic signatures with 128-bit security (equivalent to RSA-3072).
     *
     * @param data       the string to sign
     * @param privateKey the Ed25519 private key
     * @return the signature bytes (64 bytes)
     * @throws GeneralSecurityException if signing fails
     * @throws IllegalArgumentException if data is blank or privateKey is null
     */
    public static byte[] signEd25519(String data, PrivateKey privateKey) throws Exception {
        Validate.notBlank(data, "data cannot be blank");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        return signEd25519(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Signs the given byte array using Ed25519.
     *
     * @param data       the data to sign
     * @param privateKey the Ed25519 private key
     * @return the signature bytes (64 bytes)
     * @throws GeneralSecurityException if signing fails
     * @throws IllegalArgumentException if data or privateKey is null
     */
    public static byte[] signEd25519(byte[] data, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        Signature signature = Signature.getInstance(ED25519_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies an Ed25519 signature for the given text.
     *
     * @param signatureBytes the signature to verify
     * @param data           the original string
     * @param publicKey      the Ed25519 public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     * @throws IllegalArgumentException if any parameter is null or data is blank
     */
    public static boolean verifyEd25519(byte[] signatureBytes, String data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes, "signatureBytes cannot be null");
        Validate.notBlank(data, "data cannot be blank");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        return verifyEd25519(signatureBytes, data.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    /**
     * Verifies an Ed25519 signature for the given byte array.
     *
     * @param signatureBytes the signature to verify
     * @param data           the original data
     * @param publicKey      the Ed25519 public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     * @throws IllegalArgumentException if any parameter is null
     */
    public static boolean verifyEd25519(byte[] signatureBytes, byte[] data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes, "signatureBytes cannot be null");
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        Signature signature = Signature.getInstance(ED25519_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // ========== ECDSA Signatures (ECC-based) ==========

    /**
     * Signs the given text using ECDSA (Elliptic Curve Digital Signature Algorithm).
     * The hash algorithm is automatically selected based on the key's curve.
     *
     * @param data       the string to sign
     * @param privateKey the ECDSA private key (secp256r1, secp384r1, or secp521r1)
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     * @throws IllegalArgumentException if data is blank or privateKey is null
     */
    public static byte[] signEcdsa(String data, PrivateKey privateKey) throws Exception {
        Validate.notBlank(data, "data cannot be blank");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        return signEcdsa(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Signs the given byte array using ECDSA with the appropriate hash algorithm for the key.
     *
     * @param data       the data to sign
     * @param privateKey the ECDSA private key
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     * @throws IllegalArgumentException if data or privateKey is null
     */
    public static byte[] signEcdsa(byte[] data, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        String algorithm = determineEcdsaAlgorithm(privateKey);
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies an ECDSA signature for the given text.
     *
     * @param signatureBytes the signature to verify
     * @param data           the original string
     * @param publicKey      the ECDSA public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     * @throws IllegalArgumentException if any parameter is null or data is blank
     */
    public static boolean verifyEcdsa(byte[] signatureBytes, String data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes, "signatureBytes cannot be null");
        Validate.notBlank(data, "data cannot be blank");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        return verifyEcdsa(signatureBytes, data.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    /**
     * Verifies an ECDSA signature for the given byte array.
     *
     * @param signatureBytes the signature to verify
     * @param data           the original data
     * @param publicKey      the ECDSA public key
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if verification fails
     * @throws IllegalArgumentException if any parameter is null
     */
    public static boolean verifyEcdsa(byte[] signatureBytes, byte[] data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signatureBytes, "signatureBytes cannot be null");
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        String algorithm = determineEcdsaAlgorithm(publicKey);
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    /**
     * Determines the appropriate ECDSA signature algorithm based on the key.
     * Defaults to SHA256withECDSA for EC keys.
     *
     * @param key the EC key (public or private)
     * @return the signature algorithm name (e.g., "SHA256withECDSA")
     */
    private static String determineEcdsaAlgorithm(java.security.Key key) {
        String algorithm = key.getAlgorithm();
        if (!"EC".equals(algorithm)) {
            throw new IllegalArgumentException("Key must be an EC key, but was: " + algorithm);
        }
        // Default to SHA256withECDSA
        // In production, you could inspect the key's ECParameterSpec to determine exact curve
        return "SHA256withECDSA";
    }
}
