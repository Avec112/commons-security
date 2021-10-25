package io.avec.crypto.rsa;

import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.encoding.Base64;

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

        return new CipherText(Base64.encode(cipherText));
    }

    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey) throws Exception {
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] cipherTextDecoded = Base64.decode(cipherText.getValue());
        final byte[] plainText = cipher.doFinal(cipherTextDecoded);
        return new PlainText(new String(plainText));
    }
}
