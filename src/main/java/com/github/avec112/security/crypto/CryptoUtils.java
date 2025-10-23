package com.github.avec112.security.crypto;

import com.github.avec112.security.crypto.aes.AesDecryptor;
import com.github.avec112.security.crypto.aes.AesEncryptor;
import com.github.avec112.security.crypto.digest.DigestUtils;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.error.BadCipherConfigurationException;
import com.github.avec112.security.crypto.error.BadCipherTextException;
import com.github.avec112.security.crypto.hybrid.DecryptBuilder;
import com.github.avec112.security.crypto.hybrid.EncryptBuilder;
import com.github.avec112.security.crypto.hybrid.HybridEncryptionResult;
import com.github.avec112.security.crypto.password.PasswordEncoderUtils;
import com.github.avec112.security.crypto.rsa.RsaCipher;
import com.github.avec112.security.crypto.shamir.Secret;
import com.github.avec112.security.crypto.shamir.Shamir;
import com.github.avec112.security.crypto.shamir.Share;
import com.github.avec112.security.crypto.shamir.Shares;
import com.github.avec112.security.crypto.sign.SignatureUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Utility class providing cryptographic functions such as encryption, decryption, hashing, signature
 * generation/verification, and secret sharing mechanisms. This class covers a wide range of cryptographic
 * operations, including AES encryption, RSA encryption, Shamir's Secret Sharing, message digests, and hybrid encryption.
 */
public class CryptoUtils {

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

    /**
     * Signs the given data using RSASSA-PSS with the provided private key.
     *
     * @param data       the data to sign
     * @param privateKey the private key to use for signing
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
     * @param publicKey the public key to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws Exception if an error occurs during verification
     */
    public static boolean verify(byte[] signature, String data, PublicKey publicKey) throws Exception {
        return SignatureUtils.verify(signature, data, publicKey);
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
     * Matches a raw password against an encoded password using the default password encoder (ARGON2).
     *
     * @param rawPassword     the raw password to check
     * @param encodedPassword the encoded password to match against
     * @return true if the passwords match, false otherwise
     */
    public static boolean matchesPassword(String rawPassword, String encodedPassword) {
        return PasswordEncoderUtils.matches(rawPassword, encodedPassword);
    }
}
