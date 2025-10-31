package io.github.avec112.security.crypto.ecc;

/**
 * Enumeration of supported Elliptic Curve Cryptography (ECC) curves.
 *
 * <p>This enum provides standard ECC curves for various cryptographic operations:</p>
 * <ul>
 *   <li><b>Ed25519</b> - Modern EdDSA signature curve (256-bit security)</li>
 *   <li><b>secp256r1 (P-256)</b> - NIST curve for ECDSA signatures and ECIES encryption</li>
 *   <li><b>secp384r1 (P-384)</b> - NIST curve for higher security requirements</li>
 *   <li><b>secp521r1 (P-521)</b> - NIST curve for maximum security</li>
 * </ul>
 *
 * <p><b>Recommended curves:</b></p>
 * <ul>
 *   <li>Ed25519 for signatures (fastest, most modern)</li>
 *   <li>secp256r1 for general-purpose ECDSA and ECIES</li>
 *   <li>secp384r1 or secp521r1 for higher security requirements</li>
 * </ul>
 */
public enum EccCurve {
    /**
     * Ed25519 curve - Modern EdDSA signature curve providing 128-bit security.
     * Equivalent security to RSA-3072 and AES-256.
     * Fast, secure, and widely adopted in modern protocols.
     */
    ED25519("Ed25519", 256),

    /**
     * secp256r1 (also known as P-256 or prime256v1) - NIST standardized curve.
     * Provides approximately 128-bit security, equivalent to RSA-3072.
     * Widely supported for ECDSA signatures and ECIES encryption.
     */
    SECP256R1("secp256r1", 256),

    /**
     * secp384r1 (also known as P-384) - NIST standardized curve.
     * Provides approximately 192-bit security, equivalent to RSA-7680.
     * Suitable for high-security applications.
     */
    SECP384R1("secp384r1", 384),

    /**
     * secp521r1 (also known as P-521) - NIST standardized curve.
     * Provides approximately 256-bit security, equivalent to RSA-15360.
     * Maximum security level for standards-based ECC.
     */
    SECP521R1("secp521r1", 521);

    private final String curveName;
    private final int keySize;

    EccCurve(String curveName, int keySize) {
        this.curveName = curveName;
        this.keySize = keySize;
    }

    /**
     * Returns the standard curve name used by Java Security API.
     *
     * @return the curve name (e.g., "Ed25519", "secp256r1")
     */
    public String getCurveName() {
        return curveName;
    }

    /**
     * Returns the nominal key size in bits.
     *
     * @return the key size in bits
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Returns a human-readable description of the curve and its security level.
     *
     * @return description string
     */
    public String describe() {
        return String.format("%s (%d-bit)", curveName, keySize);
    }
}
