package io.avec.security.crypto.sign;

import io.avec.security.crypto.BouncyCastleProviderInitializer;
import org.apache.commons.lang3.Validate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtils extends BouncyCastleProviderInitializer {

    private SignatureUtils() {
    }

    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Validate.notBlank(data);
        Validate.notNull(privateKey);

        return sign(data.getBytes(), privateKey);
    }


    public static byte[] sign(byte [] data, PrivateKey privateKey) throws Exception {
        Validate.notNull(data);
        Validate.notNull(privateKey);

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] signature, String data, PublicKey publicKey) throws Exception {
        Validate.notNull(signature);
        Validate.notBlank(data);
        Validate.notNull(publicKey);

        return verify(signature, data.getBytes(), publicKey);
    }

    public static boolean verify(byte[] signature, byte[] data, PublicKey publicKey) throws Exception {
        Validate.notNull(signature);
        Validate.notNull(data);
        Validate.notNull(publicKey);

        Signature verifySignature = Signature.getInstance("SHA256withRSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(data);
        return verifySignature.verify(signature);
    }
}
