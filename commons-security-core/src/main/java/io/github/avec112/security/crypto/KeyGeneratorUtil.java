package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.aes.AesKeySize;
import io.github.avec112.security.crypto.ecc.EccCurve;
import io.github.avec112.security.crypto.rsa.RsaKeySize;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * A unified utility class for generating cryptographic key pairs.
 * This class extends {@code BouncyCastleProviderInitializer}, ensuring that the BouncyCastle
 * security provider is initialized before any cryptographic operations.
 *
 * <p>Supports key generation for:</p>
 * <ul>
 *   <li><b>RSA</b> - 2048, 3072 (default), and 4096 bit keys</li>
 *   <li><b>Ed25519</b> - Modern EdDSA signature curve (256-bit security)</li>
 *   <li><b>ECC (Elliptic Curve)</b> - secp256r1, secp384r1, secp521r1 for ECDSA and ECIES</li>
 * </ul>
 *
 * <p><b>Example usage:</b></p>
 * <pre>{@code
 * // RSA keys
 * KeyPair rsaKeys = KeyGeneratorUtil.generateRsaKeyPair();
 *
 * // Ed25519 keys for signatures
 * KeyPair ed25519Keys = KeyGeneratorUtil.generateEd25519KeyPair();
 *
 * // EC keys for ECDSA or ECIES
 * KeyPair ecKeys = KeyGeneratorUtil.generateEcKeyPair(EccCurve.SECP256R1);
 * }</pre>
 */
public class KeyGeneratorUtil extends BouncyCastleProviderInitializer {

    private static final RsaKeySize DEFAULT_RSA_KEY_SIZE = RsaKeySize.BIT_3072;
    private static final EccCurve DEFAULT_EC_CURVE = EccCurve.SECP256R1;

    private KeyGeneratorUtil() {
    }

    // ========== AES Key Generation ==========

    /**
     * Generates a symmetric AES key with specified key size.
     *
     * @param keySize the AES key size as {@link AesKeySize} enum (BIT_128, BIT_192, or BIT_256)
     * @return generated SecretKey for AES encryption
     * @throws NoSuchAlgorithmException if AES algorithm is not available
     */
    public static SecretKey generateAesKey(AesKeySize keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize.getKeySize());
        return keyGen.generateKey();
    }

    /**
     * Generates a 256-bit AES key (default and recommended).
     *
     * @return generated 256-bit SecretKey for AES encryption
     * @throws NoSuchAlgorithmException if AES algorithm is not available
     */
    public static SecretKey generateAesKey() throws NoSuchAlgorithmException {
        return generateAesKey(AesKeySize.BIT_256);
    }

    // ========== RSA Key Generation ==========

    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize the key size for the RSA key pair, represented as a {@link RsaKeySize} enum. It supports key sizes of
     *                1024, 2048, 3072, or 4096 bits. Using 1024 bits is deprecated and not recommended due to
     *                insufficient security strength.
     * @return a {@link KeyPair} containing the public and private RSA keys generated with the specified size.
     * @throws NoSuchAlgorithmException if the cryptographic algorithm "RSA" is not available in the environment.
     * @throws InvalidAlgorithmParameterException if the specified key size or parameters are invalid.
     */
    public static KeyPair generateRsaKeyPair(RsaKeySize keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize.getKeySize(), RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates an RSA key pair using the default key size 3072 bits.
     *
     * @return a {@link KeyPair} containing the public and private RSA keys generated using the default key size.
     * @throws Exception if an error occurs during RSA key pair generation, such as when the cryptographic algorithm
     *                   "RSA" is unavailable or an invalid key size is specified.
     */
    public static KeyPair generateRsaKeyPair() throws Exception {
        return generateRsaKeyPair(DEFAULT_RSA_KEY_SIZE);
    }

    public static KeyPair generateRsaKeyPair4096() throws Exception {
        return generateRsaKeyPair(RsaKeySize.BIT_4096);
    }

    public static KeyPair generateRsaKeyPair3072() throws Exception {
        return generateRsaKeyPair(RsaKeySize.BIT_3072);
    }

    public static KeyPair generateRsaKeyPair2048() throws Exception {
        return generateRsaKeyPair(RsaKeySize.BIT_2048);
    }

    // ========== ECC Key Generation Methods ==========

    /**
     * Generates an ECC (Elliptic Curve) key pair for the specified curve.
     * These keys can be used for ECDSA signatures or ECIES encryption.
     *
     * @param curve the elliptic curve to use (secp256r1, secp384r1, or secp521r1)
     * @return a {@link KeyPair} containing the public and private ECC keys
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve is not supported
     * @throws IllegalArgumentException if Ed25519 curve is specified (use generateEd25519KeyPair instead)
     */
    public static KeyPair generateEcKeyPair(EccCurve curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (curve == EccCurve.ED25519) {
            throw new IllegalArgumentException("Use generateEd25519KeyPair() for Ed25519 curve");
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve.getCurveName());
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates an ECC key pair using the default curve (secp256r1).
     * Provides 256-bit security, equivalent to RSA-3072.
     *
     * @return a {@link KeyPair} containing the public and private ECC keys
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve is not supported
     */
    public static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return generateEcKeyPair(DEFAULT_EC_CURVE);
    }

    /**
     * Generates an Ed25519 key pair for EdDSA signatures.
     *
     * <p>Ed25519 is a modern signature algorithm that provides:</p>
     * <ul>
     *   <li>High performance (faster than ECDSA and RSA)</li>
     *   <li>Strong security (128-bit, equivalent to RSA-3072)</li>
     *   <li>Deterministic signatures (same input always produces same signature)</li>
     *   <li>Small keys (32 bytes for public key, 32 bytes for private key)</li>
     * </ul>
     *
     * @return a {@link KeyPair} containing the Ed25519 public and private keys
     * @throws NoSuchAlgorithmException if the Ed25519 algorithm is not available
     */
    public static KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519" );
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates a secp256r1 (P-256) key pair.
     * Equivalent to 3072-bit RSA security.
     *
     * @return a {@link KeyPair} for secp256r1 curve
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve is not supported
     */
    public static KeyPair generateSecp256r1KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return generateEcKeyPair(EccCurve.SECP256R1);
    }

    /**
     * Generates a secp384r1 (P-384) key pair.
     * Equivalent to 7680-bit RSA security.
     *
     * @return a {@link KeyPair} for secp384r1 curve
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve is not supported
     */
    public static KeyPair generateSecp384r1KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return generateEcKeyPair(EccCurve.SECP384R1);
    }

    /**
     * Generates a secp521r1 (P-521) key pair.
     * Equivalent to 15360-bit RSA security.
     *
     * @return a {@link KeyPair} for secp521r1 curve
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws InvalidAlgorithmParameterException if the curve is not supported
     */
    public static KeyPair generateSecp521r1KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return generateEcKeyPair(EccCurve.SECP521R1);
    }

}
