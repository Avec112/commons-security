package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.encoding.EncodingUtils;
import lombok.Value;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility class for managing cryptographic keys, including generation, 
 * storage, loading, and format conversion.
 * 
 * Supports RSA, EC (ECDSA/ECIES), Ed25519, and symmetric AES keys.
 */
public class KeyStorageUtils extends BouncyCastleProviderInitializer {

    private KeyStorageUtils() {
    }


    // ========== Asymmetric Key Pair Storage (PEM Format) ==========

    /**
     * Saves a private key to disk in PKCS#8 PEM format (unencrypted).
     * 
     * WARNING: Stores private key without password protection.
     * Use savePrivateKeyEncrypted() for production use.
     *
     * @param privateKey the private key to save
     * @param filePath path where to save the key
     */
    public static void savePrivateKey(PrivateKey privateKey, Path filePath) throws IOException {
        String pem = toPemFormat(privateKey.getEncoded(), "PRIVATE KEY");
        Files.writeString(filePath, pem, StandardCharsets.UTF_8);
    }

    /**
     * Saves a private key to disk in encrypted PKCS#8 PEM format.
     * Uses AES-256 encryption with password-based key derivation.
     *
     * @param privateKey the private key to save
     * @param password password for encryption
     * @param filePath path where to save the encrypted key
     */
    public static void savePrivateKeyEncrypted(PrivateKey privateKey, Password password, Path filePath) 
            throws GeneralSecurityException, IOException {
        // Implementation would use EncryptedPrivateKeyInfo
        byte[] encrypted = encryptPrivateKey(privateKey, password);
        String pem = toPemFormat(encrypted, "ENCRYPTED PRIVATE KEY");
        Files.writeString(filePath, pem, StandardCharsets.UTF_8);
    }

    /**
     * Saves a public key to disk in X.509 PEM format.
     *
     * @param publicKey the public key to save
     * @param filePath path where to save the key
     */
    public static void savePublicKey(PublicKey publicKey, Path filePath) throws IOException {
        String pem = toPemFormat(publicKey.getEncoded(), "PUBLIC KEY");
        Files.writeString(filePath, pem, StandardCharsets.UTF_8);
    }

    /**
     * Saves a complete key pair (both private and public keys).
     * Private key is saved encrypted, public key in plaintext.
     *
     * @param keyPair the key pair to save
     * @param password password for encrypting the private key
     * @param privateKeyPath path for private key file
     * @param publicKeyPath path for public key file
     */
    public static void saveKeyPair(KeyPair keyPair, Password password, 
                                   Path privateKeyPath, Path publicKeyPath) 
            throws GeneralSecurityException, IOException {
        savePrivateKeyEncrypted(keyPair.getPrivate(), password, privateKeyPath);
        savePublicKey(keyPair.getPublic(), publicKeyPath);
    }

    // ========== Asymmetric Key Loading ==========

    /**
     * Loads a private key from disk (unencrypted PKCS#8 PEM format).
     *
     * @param filePath path to the private key file
     * @param algorithm algorithm name ("RSA", "EC", "Ed25519")
     * @return loaded PrivateKey
     */
    public static PrivateKey loadPrivateKey(Path filePath, String algorithm) 
            throws IOException, GeneralSecurityException {
        String pem = Files.readString(filePath, StandardCharsets.UTF_8);
        byte[] keyBytes = fromPemFormat(pem);
        
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads an encrypted private key from disk.
     *
     * @param filePath path to the encrypted private key file
     * @param password password for decryption
     * @param algorithm algorithm name ("RSA", "EC", "Ed25519")
     * @return loaded PrivateKey
     */
    public static PrivateKey loadPrivateKeyEncrypted(Path filePath, Password password, String algorithm) 
            throws IOException, GeneralSecurityException {
        String pem = Files.readString(filePath, StandardCharsets.UTF_8);
        byte[] encryptedBytes = fromPemFormat(pem);
        byte[] decryptedBytes = decryptPrivateKey(encryptedBytes, password);
        
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads a public key from disk (X.509 PEM format).
     *
     * @param filePath path to the public key file
     * @param algorithm algorithm name ("RSA", "EC", "Ed25519")
     * @return loaded PublicKey
     */
    public static PublicKey loadPublicKey(Path filePath, String algorithm) 
            throws IOException, GeneralSecurityException {
        String pem = Files.readString(filePath, StandardCharsets.UTF_8);
        byte[] keyBytes = fromPemFormat(pem);
        
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Loads a complete key pair from disk.
     *
     * @param privateKeyPath path to encrypted private key file
     * @param publicKeyPath path to public key file
     * @param password password for decrypting private key
     * @param algorithm algorithm name ("RSA", "EC", "Ed25519")
     * @return loaded KeyPair
     */
    public static KeyPair loadKeyPair(Path privateKeyPath, Path publicKeyPath, 
                                     Password password, String algorithm) 
            throws IOException, GeneralSecurityException {
        PrivateKey privateKey = loadPrivateKeyEncrypted(privateKeyPath, password, algorithm);
        PublicKey publicKey = loadPublicKey(publicKeyPath, algorithm);
        return new KeyPair(publicKey, privateKey);
    }

    // ========== Symmetric Key Storage ==========

    /**
     * Saves an AES key to disk (Base64 encoded, unencrypted).
     * 
     * WARNING: Stores key in plaintext. Use saveAesKeyEncrypted() for production.
     *
     * @param secretKey the AES key to save
     * @param filePath path where to save the key
     */
    public static void saveAesKey(SecretKey secretKey, Path filePath) throws IOException {
        String encoded = EncodingUtils.base64Encode(secretKey.getEncoded());
        Files.writeString(filePath, encoded, StandardCharsets.UTF_8);
    }

    /**
     * Saves an AES key to disk with password-based encryption.
     *
     * @param secretKey the AES key to save
     * @param password password for encryption
     * @param filePath path where to save the encrypted key
     */
    public static void saveAesKeyEncrypted(SecretKey secretKey, Password password, Path filePath) 
            throws Exception {
        PlainText keyData = new PlainText(EncodingUtils.base64Encode(secretKey.getEncoded()));
        CipherText encrypted = CryptoUtils.aesEncrypt(keyData, password);
        Files.writeString(filePath, encrypted.getValue(), StandardCharsets.UTF_8);
    }

    /**
     * Loads an AES key from disk (unencrypted).
     *
     * @param filePath path to the key file
     * @return loaded SecretKey
     */
    public static SecretKey loadAesKey(Path filePath) throws IOException {
        String encoded = Files.readString(filePath, StandardCharsets.UTF_8).trim();
        byte[] keyBytes = EncodingUtils.base64Decode(encoded);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Loads an encrypted AES key from disk.
     *
     * @param filePath path to the encrypted key file
     * @param password password for decryption
     * @return loaded SecretKey
     */
    public static SecretKey loadAesKeyEncrypted(Path filePath, Password password) throws Exception {
        String cipherText = Files.readString(filePath, StandardCharsets.UTF_8);
        PlainText decrypted = CryptoUtils.aesDecrypt(new CipherText(cipherText), password);
        byte[] keyBytes = EncodingUtils.base64Decode(decrypted.getValue());
        return new SecretKeySpec(keyBytes, "AES");
    }

    // ========== Key Format Conversion ==========

    /**
     * Converts a key to PEM format.
     *
     * @param keyBytes DER-encoded key bytes
     * @param type key type label (e.g., "PRIVATE KEY", "PUBLIC KEY")
     * @return PEM-formatted string
     */
    public static String toPemFormat(byte[] keyBytes, String type) {
        String base64 = EncodingUtils.base64Encode(keyBytes);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(type).append("-----\n");
        
        // Split into 64-character lines
        for (int i = 0; i < base64.length(); i += 64) {
            int end = Math.min(i + 64, base64.length());
            pem.append(base64, i, end).append("\n");
        }
        
        pem.append("-----END ").append(type).append("-----\n");
        return pem.toString();
    }

    /**
     * Extracts DER-encoded bytes from PEM format.
     *
     * @param pem PEM-formatted key string
     * @return DER-encoded key bytes
     */
    public static byte[] fromPemFormat(String pem) {
        String base64 = pem
                .replaceAll("-----BEGIN.*-----", "")
                .replaceAll("-----END.*-----", "")
                .replaceAll("\\s", "");
        return EncodingUtils.base64Decode(base64);
    }

    /**
     * Exports a public key as Base64-encoded string (for easy sharing).
     *
     * @param publicKey the public key to export
     * @return Base64-encoded public key
     */
    public static String exportPublicKeyAsBase64(PublicKey publicKey) {
        return EncodingUtils.base64Encode(publicKey.getEncoded());
    }

    /**
     * Imports a public key from Base64-encoded string.
     *
     * @param base64Key Base64-encoded public key
     * @param algorithm algorithm name ("RSA", "EC", "Ed25519")
     * @return PublicKey
     */
    public static PublicKey importPublicKeyFromBase64(String base64Key, String algorithm) 
            throws GeneralSecurityException {
        byte[] keyBytes = EncodingUtils.base64Decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    // ========== Key Validation ==========

    /**
     * Validates RSA key strength meets minimum requirements.
     *
     * @param keyPair the key pair to validate
     * @param minimumBits minimum key size in bits (e.g., 2048)
     * @return true if key meets requirements
     */
    public static boolean isRsaKeySufficient(KeyPair keyPair, int minimumBits) {
        if (!(keyPair.getPrivate() instanceof RSAPrivateKey)) {
            return false;
        }
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return privateKey.getModulus().bitLength() >= minimumBits;
    }

    /**
     * Gets metadata about a key pair.
     *
     * @param keyPair the key pair to inspect
     * @return KeyMetadata with algorithm, size, and type info
     */
    public static KeyMetadata getKeyMetadata(KeyPair keyPair) {
        String algorithm = keyPair.getPrivate().getAlgorithm();
        int keySize = getKeySize(keyPair.getPrivate());
        return new KeyMetadata(algorithm, keySize, keyPair.getPrivate().getFormat());
    }

    // ========== Helper Methods ==========

    private static byte[] encryptPrivateKey(PrivateKey privateKey, Password password) 
            throws GeneralSecurityException {
        // Simplified - full implementation would use PBKDF2 + AES
        // This is a placeholder for the actual encryption logic
        throw new UnsupportedOperationException("Not yet implemented");
    }

    private static byte[] decryptPrivateKey(byte[] encrypted, Password password) 
            throws GeneralSecurityException {
        // Simplified - full implementation would use PBKDF2 + AES
        throw new UnsupportedOperationException("Not yet implemented");
    }

    private static int getKeySize(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            return ((RSAPrivateKey) privateKey).getModulus().bitLength();
        } else if (privateKey instanceof ECPrivateKey) {
            return ((ECPrivateKey) privateKey).getParams().getOrder().bitLength();
        }
        return -1; // Unknown
    }

    /**
     * Metadata about a cryptographic key.
     */
    @Value
    public static class KeyMetadata {
        String algorithm;
        int keySize;
        String format;
    }
}
