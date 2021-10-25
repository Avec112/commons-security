package io.avec.security.crypto;

import io.avec.security.crypto.aes.AesCipher;
import io.avec.security.crypto.domain.CipherText;
import io.avec.security.crypto.domain.Password;
import io.avec.security.crypto.domain.PlainText;
import io.avec.security.crypto.rsa.RsaCipher;
import io.avec.security.crypto.shamir.Secret;
import io.avec.security.crypto.shamir.Shamir;
import io.avec.security.crypto.shamir.Share;
import io.avec.security.crypto.shamir.Shares;

import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptoUtils {

    private CryptoUtils() {
    }

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
