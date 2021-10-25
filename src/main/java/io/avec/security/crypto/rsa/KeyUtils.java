package io.avec.security.crypto.rsa;

import org.apache.commons.lang3.Validate;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyUtils {

    private KeyUtils() {
    }

    public static KeyPair generateKeyPair4096() throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.generateKeyPair(KeySize.BIT_4096);
    }

    public static KeyPair generateKeyPair2048() throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.generateKeyPair(KeySize.BIT_2048);
    }

    public static KeyPair generateKeyPair1024() throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.generateKeyPair(KeySize.BIT_1024);
    }

    public static KeyPair generateKeyPair(KeySize keySize) throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.generateKeyPair(keySize);
    }

    public static void validateRsaKeyPair(KeyPair keyPair, KeySize keySize) {

        try {
            Validate.notNull(keyPair);
            Validate.notNull(keySize);
            Validate.isInstanceOf(RSAPublicKey.class, keyPair.getPublic(), "Public Key is not a RSAPublicKey");
            final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            Validate.isTrue(publicKey.getAlgorithm().equals("RSA"), "Algorithm must be RSA");
            Validate.isTrue(publicKey.getFormat().equals("X.509"), "Public key format must be X.509");
            Validate.isTrue(publicKey.getModulus().bitLength() == keySize.getKeySize(), "Key size expected to be %s", keySize.getKeySize());

            Validate.isInstanceOf(RSAPrivateKey.class, keyPair.getPrivate(), "Private Key is not a RSAPrivateKey");
            final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            Validate.isTrue(privateKey.getAlgorithm().equals("RSA"), "Algorithm must be RSA");
            Validate.isTrue(privateKey.getFormat().equals("PKCS#8"), "Private key format must be PKCS#8");
            Validate.isTrue(privateKey.getModulus().bitLength() == keySize.getKeySize(), "Key size expected to be %s", keySize.getKeySize());
        } catch(Exception e) {
            throw new RsaKeyException(e.getMessage());
        }
    }
}
