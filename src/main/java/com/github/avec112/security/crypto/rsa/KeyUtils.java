package com.github.avec112.security.crypto.rsa;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

public class KeyUtils extends BouncyCastleProviderInitializer {

    private KeyUtils() {
    }

    public static KeyPair generateRsaKeyPair(KeySize keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize.getKeySize(), RSAKeyGenParameterSpec.F4));
//        keyPairGenerator.initialize(keySize.getKeySize());
        return keyPairGenerator.generateKeyPair();
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

    public static KeyPair generateKeyPair1024() throws Exception {
        return generateRsaKeyPair(KeySize.BIT_1024);
    }



}
