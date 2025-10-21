package com.github.avec112.security.crypto.rsa;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * A utility class for generating RSA key pairs with configurable or pre-defined key sizes.
 * This class extends {@code BouncyCastleProviderInitializer}, ensuring that the BouncyCastle
 * security provider is initialized before any cryptographic operations.
 *
 * This utility supports RSA key pair generation with key sizes of 1024, 2048, 3072, and 4096 bits.
 * The default key size is set to 3072 bits.
 */
public class KeyUtils extends BouncyCastleProviderInitializer {

    private static final KeySize DEFAULT_KEY_SIZE = KeySize.BIT_3072;

    private KeyUtils() {
    }


    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize the key size for the RSA key pair, represented as a {@link KeySize} enum. It supports key sizes of
     *                1024, 2048, 3072, or 4096 bits. Using 1024 bits is deprecated and not recommended due to
     *                insufficient security strength.
     * @return a {@link KeyPair} containing the public and private RSA keys generated with the specified size.
     * @throws NoSuchAlgorithmException if the cryptographic algorithm "RSA" is not available in the environment.
     * @throws InvalidAlgorithmParameterException if the specified key size or parameters are invalid.
     */
    public static KeyPair generateRsaKeyPair(KeySize keySize ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
        return generateRsaKeyPair(DEFAULT_KEY_SIZE);
    }

    public static KeyPair generateKeyPair4096() throws Exception {
        return generateRsaKeyPair(KeySize.BIT_4096);
    }

    public static KeyPair generateKeyPair3072() throws Exception {
        return generateRsaKeyPair(KeySize.BIT_3072);
    }

    public static KeyPair generateKeyPair2048() throws Exception {
        return generateRsaKeyPair(KeySize.BIT_2048);
    }

}
