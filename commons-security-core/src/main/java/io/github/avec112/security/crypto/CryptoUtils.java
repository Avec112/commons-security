package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.aes.AesDecryptor;
import io.github.avec112.security.crypto.aes.AesEncryptor;
import io.github.avec112.security.crypto.digest.DigestUtils;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.ecc.EciesCipher;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.crypto.error.BadCipherTextException;
import io.github.avec112.security.crypto.hybrid.DecryptBuilder;
import io.github.avec112.security.crypto.hybrid.EncryptBuilder;
import io.github.avec112.security.crypto.hybrid.HybridEncryptionResult;
import io.github.avec112.security.crypto.password.PasswordEncoderUtils;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.shamir.Secret;
import io.github.avec112.security.crypto.shamir.Shamir;
import io.github.avec112.security.crypto.shamir.Share;
import io.github.avec112.security.crypto.shamir.Shares;
import io.github.avec112.security.crypto.sign.SignatureUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Utility class providing cryptographic functions such as encryption, decryption, hashing, signature
 * generation/verification, and secret sharing mechanisms. This class covers a wide range of cryptographic
 * operations, including AES encryption, RSA encryption, ECC signatures (Ed25519, ECDSA), ECIES encryption,
 * Shamir's Secret Sharing, message digests, and hybrid encryption.
 */
public class CryptoUtils {

    /**
     * The version of the commons-security library.
     * This follows semantic versioning (MAJOR.MINOR.PATCH).
     * Should match version inside pom.xml.
     */
    private static final String VERSION = "0.9.0-SNAPSHOT";

    private CryptoUtils() {
    }

    // ========== Symmetric Encryption Methods ==========

    /**
     * Encrypts the provided plaintext using AES encryption with the given password.
     *
     * @param plainText the plaintext to encrypt
     * @param password the password to use for encryption
     * @return the encrypted ciphertext
     * @throws BadCipherConfigurationException if an error occurs during encryption configuration
     */
    public static CipherText aesEncrypt(PlainText plainText, Password password) throws BadCipherConfigurationException {
        return AesEncryptor.withPasswordAndText(password, plainText).encrypt();
    }

    /**
     * Decrypts the provided ciphertext using AES decryption with the given password.
     *
     * @param ciperText the ciphertext to be decrypted
     * @param password the password to use for decryption
     * @return the decrypted plaintext
     * @throws BadCipherConfigurationException if an error occurs during decryption configuration
     * @throws BadCipherTextException if the provided ciphertext is invalid or decryption fails
     */
    public static PlainText aesDecrypt(CipherText ciperText, Password password) throws BadCipherConfigurationException, BadCipherTextException {
        return AesDecryptor.withPasswordAndCipherText(password, ciperText).decrypt();
    }

    // ========== Asymmetric Encryption Methods ==========

    // RSA Encryption

    /**
     * Encrypts the provided plaintext using RSA encryption with the given public key.
     *
     * @param plainText the plaintext to encrypt
     * @param publicKey the public key to use for encryption
     * @return the encrypted ciphertext
     * @throws Exception if an error occurs during encryption
     */
    public static CipherText rsaEncrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.encrypt(plainText, publicKey);
    }

    /**
     * Decrypts the provided ciphertext using RSA decryption with the given private key.
     *
     * @param ciperText the ciphertext to be decrypted
     * @param privateKey the private key to use for decryption
     * @return the decrypted plaintext
     * @throws Exception if an error occurs during decryption
     */
    public static PlainText rsaDecrypt(CipherText ciperText, PrivateKey privateKey) throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.decrypt(ciperText, privateKey);
    }

    // ECIES Encryption (ECC-based)

    /**
     * Encrypts plaintext using ECIES (Elliptic Curve Integrated Encryption Scheme).
     * ECIES is a hybrid encryption scheme that combines ECC key agreement with symmetric encryption.
     *
     * @param plainText the plaintext to encrypt
     * @param publicKey the recipient's EC public key (secp256r1, secp384r1, or secp521r1)
     * @return the encrypted ciphertext bytes
     * @throws Exception if an error occurs during encryption
     */
    public static byte[] eciesEncrypt(String plainText, PublicKey publicKey) throws Exception {
        return EciesCipher.encrypt(plainText, publicKey);
    }

    /**
     * Decrypts ECIES ciphertext using the recipient's private key.
     *
     * @param ciphertext the encrypted data
     * @param privateKey the recipient's EC private key
     * @return the decrypted plaintext string
     * @throws Exception if an error occurs during decryption
     */
    public static String eciesDecrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        return EciesCipher.decrypt(ciphertext, privateKey);
    }

    // ========== Shamir's Secret Sharing Methods ==========

    /**
     * Splits a secret into multiple shares using Shamir's Secret Sharing scheme.
     *
     * @param secret the secret to be divided into shares
     * @param keysTotal the total number of shares to generate
     * @param keysMinimum the minimum number of shares required to reconstruct the secret
     * @return a {@code Shares} object containing the generated shares
     */
    public static Shares getShamirShares(Secret secret, int keysTotal, int keysMinimum) {
        return Shamir.getShares(secret, keysTotal, keysMinimum);
    }

    /**
     * Reconstructs a secret using Shamir's Secret Sharing scheme from the provided shares.
     *
     * @param shares the shares to be combined to reconstruct the secret
     * @return the reconstructed secret
     */
    public static Secret getShamirSecret(Share...shares) {
        return Shamir.getSecret(shares);
    }

    // ========== Digest Methods ==========

    /**
     * Creates a SHA-512/256 digest of the given data.
     *
     * @param data the data to digest
     * @return the digest as a byte array
     * @throws Exception if an error occurs during digesting
     */
    public static byte[] digest(String data) throws Exception {
        return DigestUtils.digest(data);
    }

    /**
     * Creates a SHA-512/256 digest of the given data, encoded as Base64.
     *
     * @param data the data to digest
     * @return the Base64-encoded digest
     * @throws Exception if an error occurs during digesting
     */
    public static String base64Digest(String data) throws Exception {
        return DigestUtils.base64Digest(data);
    }

    /**
     * Creates a SHA-512/256 digest of the given data, encoded as hexadecimal.
     *
     * @param data the data to digest
     * @return the hex-encoded digest
     * @throws Exception if an error occurs during digesting
     */
    public static String hexDigest(String data) throws Exception {
        return DigestUtils.hexDigest(data);
    }

    // ========== Signature Methods ==========

    // RSA Signatures

    /**
     * Signs the given data using RSASSA-PSS with the provided private key.
     *
     * @param data       the data to sign
     * @param privateKey the RSA private key to use for signing
     * @return the signature as a byte array
     * @throws Exception if an error occurs during signing
     */
    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        return SignatureUtils.sign(data, privateKey);
    }

    /**
     * Verifies a signature for the given data using RSASSA-PSS with the provided public key.
     *
     * @param signature the signature to verify
     * @param data      the original data
     * @param publicKey the RSA public key to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws Exception if an error occurs during verification
     */
    public static boolean verify(byte[] signature, String data, PublicKey publicKey) throws Exception {
        return SignatureUtils.verify(signature, data, publicKey);
    }

    // Ed25519 Signatures (ECC-based, modern and fast)

    /**
     * Signs the given data using Ed25519.
     * Ed25519 provides fast, deterministic signatures with 128-bit security (equivalent to RSA-3072).
     *
     * @param data       the data to sign
     * @param privateKey the Ed25519 private key to use for signing
     * @return the signature as a byte array (64 bytes)
     * @throws Exception if an error occurs during signing
     */
    public static byte[] signEd25519(String data, PrivateKey privateKey) throws Exception {
        return SignatureUtils.signEd25519(data, privateKey);
    }

    /**
     * Verifies an Ed25519 signature for the given data.
     *
     * @param signature the signature to verify
     * @param data      the original data
     * @param publicKey the Ed25519 public key to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws Exception if an error occurs during verification
     */
    public static boolean verifyEd25519(byte[] signature, String data, PublicKey publicKey) throws Exception {
        return SignatureUtils.verifyEd25519(signature, data, publicKey);
    }

    // ECDSA Signatures (ECC-based, standards-compliant)

    /**
     * Signs the given data using ECDSA (Elliptic Curve Digital Signature Algorithm).
     * The hash algorithm is automatically selected based on the key's curve.
     *
     * @param data       the data to sign
     * @param privateKey the ECDSA private key (secp256r1, secp384r1, or secp521r1)
     * @return the signature as a byte array
     * @throws Exception if an error occurs during signing
     */
    public static byte[] signEcdsa(String data, PrivateKey privateKey) throws Exception {
        return SignatureUtils.signEcdsa(data, privateKey);
    }

    /**
     * Verifies an ECDSA signature for the given data.
     *
     * @param signature the signature to verify
     * @param data      the original data
     * @param publicKey the ECDSA public key
     * @return true if the signature is valid, false otherwise
     * @throws Exception if an error occurs during verification
     */
    public static boolean verifyEcdsa(byte[] signature, String data, PublicKey publicKey) throws Exception {
        return SignatureUtils.verifyEcdsa(signature, data, publicKey);
    }

    // ========== Hybrid Encryption Methods ==========

    /**
     * Performs hybrid encryption on the given plaintext using the provided public key.
     * This combines RSA encryption (for the symmetric key) with AES-GCM encryption (for the data).
     *
     * @param plainText the plaintext to encrypt
     * @param publicKey the public key to use for encrypting the symmetric key
     * @return a HybridEncryptionResult containing the encrypted data and metadata
     * @throws Exception if an error occurs during encryption
     */
    public static HybridEncryptionResult hybridEncrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        return EncryptBuilder.encryptionBuilder()
                .plainText(plainText)
                .key(publicKey)
                .build();
    }

    /**
     * Decrypts data encrypted using hybrid encryption.
     *
     * @param result     the HybridEncryptionResult containing the encrypted data and metadata
     * @param privateKey the private key to use for decrypting the symmetric key
     * @return the decrypted plaintext
     * @throws Exception if an error occurs during decryption
     */
    public static PlainText hybridDecrypt(HybridEncryptionResult result, PrivateKey privateKey) throws Exception {
        return DecryptBuilder.decryptionBuilder()
                .key(privateKey)
                .cipherText(result.getCipherText())
                .encryptedKey(result.getEncryptedKey())
                .withMode(result.getAesEncryptionMode())
                .withStrength(result.getAesEncryptionStrength())
                .build();
    }

    // ========== Password Encoding Methods ==========

    /**
     * Encodes a raw password using the default password encoder (ARGON2).
     * The encoded password can be safely stored and later used for matching.
     *
     * @param rawPassword the raw password to encode
     * @return the encoded password string
     */
    public static String encodePassword(String rawPassword) {
        return PasswordEncoderUtils.encode(rawPassword);
    }

    /**
     * Matches a raw password against an encoded password.
     * Automatically detects the encoder type from the {id} prefix in the encoded password.
     *
     * @param rawPassword     the raw password to check
     * @param encodedPassword the encoded password to match against
     * @return true if the passwords match, false otherwise
     * @throws IllegalArgumentException if the encoded password doesn't have a valid prefix
     */
    public static boolean matchesPassword(String rawPassword, String encodedPassword) {
        return PasswordEncoderUtils.matches(rawPassword, encodedPassword);
    }

    /**
     * Checks if an encoded password needs to be upgraded to the default algorithm (ARGON2).
     *
     * @param encodedPassword the currently encoded password
     * @return true if the password should be re-encoded with ARGON2
     */
    public static boolean needsPasswordUpgrade(String encodedPassword) {
        return PasswordEncoderUtils.needsUpgrade(encodedPassword);
    }

    /**
     * Upgrades an encoded password to the default encoder type (ARGON2).
     * This method verifies the raw password against the old encoded password,
     * and if valid, re-encodes it with ARGON2.
     *
     * @param rawPassword the plaintext password to verify and re-encode
     * @param oldEncodedPassword the currently encoded password
     * @return the newly encoded password with ARGON2
     * @throws IllegalArgumentException if the raw password does not match the old encoded password
     */
    public static String upgradePassword(String rawPassword, String oldEncodedPassword) {
        return PasswordEncoderUtils.upgradePassword(rawPassword, oldEncodedPassword);
    }


    /**
     * Retrieves the current version of the CryptoUtils utility.
     *
     * @return a string representing the version of the CryptoUtils utility
     */
    public static String getVersion() {
        return VERSION;
    }
}
