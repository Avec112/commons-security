package com.github.avec112.security.crypto.ecc;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * ECIES (Elliptic Curve Integrated Encryption Scheme) cipher implementation.
 *
 * <p>ECIES is a hybrid encryption scheme that combines the benefits of:</p>
 * <ul>
 *   <li><b>Asymmetric encryption</b> - Uses EC public/private keys</li>
 *   <li><b>Symmetric encryption</b> - Uses AES for actual data encryption (efficient for large data)</li>
 *   <li><b>Key derivation</b> - Derives encryption keys from ECDH shared secret</li>
 *   <li><b>Authentication</b> - Includes MAC for integrity verification</li>
 * </ul>
 *
 * <p>ECIES is the ECC equivalent of RSA-OAEP hybrid encryption, but with smaller keys and better performance.</p>
 *
 * <p><b>Advantages over RSA:</b></p>
 * <ul>
 *   <li>256-bit ECC keys provide same security as 3072-bit RSA keys</li>
 *   <li>Faster encryption and decryption</li>
 *   <li>Smaller ciphertext overhead</li>
 *   <li>Built-in integrity protection (MAC)</li>
 * </ul>
 *
 * <p><b>Example usage:</b></p>
 * <pre>{@code
 * KeyPair keyPair = EccKeyUtils.generateSecp256r1KeyPair();
 *
 * // Encrypt
 * String plaintext = "Secret message";
 * byte[] ciphertext = EciesCipher.encrypt(plaintext, keyPair.getPublic());
 *
 * // Decrypt
 * String decrypted = EciesCipher.decrypt(ciphertext, keyPair.getPrivate());
 * }</pre>
 */
public class EciesCipher extends BouncyCastleProviderInitializer {

    private static final String ALGORITHM = "ECIES";

    // ECIES parameters: derivation and encoding parameters for KDF and MAC
    // These are standard parameters that work with BouncyCastle's ECIES implementation
    private static final byte[] DEFAULT_DERIVATION = new byte[0];
    private static final byte[] DEFAULT_ENCODING = new byte[0];
    private static final int MAC_KEY_SIZE = 128; // bits
    private static final int CIPHER_KEY_SIZE = 128; // bits

    private EciesCipher() {
    }

    /**
     * Encrypts a plaintext string using ECIES with the recipient's public key.
     *
     * @param plaintext the text to encrypt
     * @param publicKey the recipient's EC public key (secp256r1, secp384r1, or secp521r1)
     * @return the encrypted ciphertext bytes
     * @throws Exception if encryption fails
     * @throws IllegalArgumentException if plaintext is null or publicKey is null
     */
    public static byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(plaintext, "plaintext cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        return encrypt(plaintext.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    /**
     * Encrypts plaintext bytes using ECIES with the recipient's public key.
     *
     * @param plaintext the data to encrypt
     * @param publicKey the recipient's EC public key
     * @return the encrypted ciphertext bytes
     * @throws Exception if encryption fails
     * @throws IllegalArgumentException if plaintext or publicKey is null
     */
    public static byte[] encrypt(byte[] plaintext, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(plaintext, "plaintext cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Public key must be an EC key");
        }

        IESParameterSpec params = new IESParameterSpec(
                DEFAULT_DERIVATION,
                DEFAULT_ENCODING,
                MAC_KEY_SIZE,
                CIPHER_KEY_SIZE,
                null
        );

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypts ECIES ciphertext using the recipient's private key.
     *
     * @param ciphertext the encrypted data
     * @param privateKey the recipient's EC private key
     * @return the decrypted plaintext string
     * @throws Exception if decryption fails
     * @throws IllegalArgumentException if ciphertext or privateKey is null
     */
    public static String decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(ciphertext, "ciphertext cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        byte[] plaintext = decryptToBytes(ciphertext, privateKey);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts ECIES ciphertext to plaintext bytes using the recipient's private key.
     *
     * @param ciphertext the encrypted data
     * @param privateKey the recipient's EC private key
     * @return the decrypted plaintext bytes
     * @throws Exception if decryption fails
     * @throws IllegalArgumentException if ciphertext or privateKey is null
     */
    public static byte[] decryptToBytes(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(ciphertext, "ciphertext cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("Private key must be an EC key");
        }

        IESParameterSpec params = new IESParameterSpec(
                DEFAULT_DERIVATION,
                DEFAULT_ENCODING,
                MAC_KEY_SIZE,
                CIPHER_KEY_SIZE,
                null
        );

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
        return cipher.doFinal(ciphertext);
    }
}
