package com.github.avec112.security.crypto.sign;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import org.apache.commons.lang3.Validate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

public class SignatureUtils extends BouncyCastleProviderInitializer {

    private SignatureUtils() {
    }

    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Validate.notBlank(data);
        Objects.requireNonNull(privateKey);

        return sign(data.getBytes(), privateKey);
    }


    public static byte[] sign(byte [] data, PrivateKey privateKey) throws Exception {
        Objects.requireNonNull(data);
        Objects.requireNonNull(privateKey);

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] signature, String data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signature);
        Validate.notBlank(data);
        Objects.requireNonNull(publicKey);

        return verify(signature, data.getBytes(), publicKey);
    }

    public static boolean verify(byte[] signature, byte[] data, PublicKey publicKey) throws Exception {
        Objects.requireNonNull(signature);
        Objects.requireNonNull(data);
        Objects.requireNonNull(publicKey);

        Signature verifySignature = Signature.getInstance("SHA256withRSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(data);
        return verifySignature.verify(signature);
    }
}
