package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.encoding.EncodingUtils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaCipher extends BouncyCastleProviderInitializer {

    public CipherText encrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        final Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        final byte[] cipherText = cipher.doFinal(plainText.getValue().getBytes(StandardCharsets.UTF_8));

        return new CipherText(EncodingUtils.base64Encode(cipherText));
    }

    public PlainText decrypt(CipherText cipherText, PrivateKey privateKey) throws Exception {
        final Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] cipherTextDecoded = EncodingUtils.base64Decode(cipherText.getValue());
        final byte[] plainText = cipher.doFinal(cipherTextDecoded);
        return new PlainText(new String(plainText));
    }
}
