package io.avec.security.crypto.rsa;

import io.avec.security.crypto.domain.CipherText;
import io.avec.security.crypto.domain.PlainText;
import io.avec.security.encoding.EncodingUtils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class RsaCipher {

    public KeyPair generateKeyPair(KeySize keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize.getKeySize());
        return keyPairGenerator.generateKeyPair();
    }

    public CipherText encrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        final byte[] cipherText = cipher.doFinal(plainText.getValue().getBytes(StandardCharsets.UTF_8));

        return new CipherText(EncodingUtils.base64Encode(cipherText));
    }

    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey) throws Exception {
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] cipherTextDecoded = EncodingUtils.base64Decode(cipherText.getValue());
        final byte[] plainText = cipher.doFinal(cipherTextDecoded);
        return new PlainText(new String(plainText));
    }
}
