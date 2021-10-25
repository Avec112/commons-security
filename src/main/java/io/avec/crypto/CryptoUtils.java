package io.avec.crypto;

import io.avec.crypto.aes.AesCipher;
import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.rsa.RsaCipher;
import io.avec.crypto.shared.Shamir;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

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

    public static List<Password> shamirSplit(PlainText plainText, int keysTotal, int keysMinimum) {
        return Shamir.getShares(plainText, keysTotal, keysMinimum);
    }

    public static PlainText shamirJoin(Password...passwords) {
        return Shamir.getSecret(passwords);
    }
}
