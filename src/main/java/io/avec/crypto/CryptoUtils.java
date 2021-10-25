package io.avec.crypto;

import io.avec.crypto.aes.AesCipher;
import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.rsa.RsaCipher;
import io.avec.crypto.shared.Secret;
import io.avec.crypto.shared.Shamir;
import io.avec.crypto.shared.Share;
import io.avec.crypto.shared.Shares;

import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptoUtils {

    public static CipherText aesEncrypt(PlainText plainText, Password password) throws Exception {
        AesCipher cipher = new AesCipher();
        return cipher.encrypt(plainText, password);
    }

    public static PlainText aesDecrypt(CipherText ciperText, Password password) throws Exception {
        AesCipher cipher = new AesCipher();
        return cipher.decrypt(ciperText, password);
    }

    public static CipherText rsaEncrypt(PlainText plainText, PublicKey publicKey) throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.encrypt(plainText, publicKey);
    }

    public static PlainText rsaDecrypt(CipherText ciperText, PrivateKey privateKey) throws Exception {
        RsaCipher cipher = new RsaCipher();
        return cipher.decrypt(ciperText, privateKey);
    }

    public static Shares getShamirShares(Secret secret, int keysTotal, int keysMinimum) {
        return Shamir.getShares(secret, keysTotal, keysMinimum);
    }

    public static Secret getShamirSecret(Share...shares) {
        return Shamir.getSecret(shares);
    }
}
