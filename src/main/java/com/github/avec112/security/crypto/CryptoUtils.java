package com.github.avec112.security.crypto;

import com.github.avec112.security.crypto.aes.AesDecryptor;
import com.github.avec112.security.crypto.aes.AesEncryptor;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.error.BadCipherConfigurationException;
import com.github.avec112.security.crypto.error.BadCipherTextException;
import com.github.avec112.security.crypto.rsa.RsaCipher;
import com.github.avec112.security.crypto.shamir.Secret;
import com.github.avec112.security.crypto.shamir.Shamir;
import com.github.avec112.security.crypto.shamir.Share;
import com.github.avec112.security.crypto.shamir.Shares;

import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptoUtils {

    private CryptoUtils() {
    }

    public static CipherText aesEncrypt(PlainText plainText, Password password) throws BadCipherConfigurationException {
        return AesEncryptor.withPasswordAndText(password, plainText).encrypt();
    }

    public static PlainText aesDecrypt(CipherText ciperText, Password password) throws BadCipherConfigurationException, BadCipherTextException {
        return AesDecryptor.withPasswordAndCipherText(password, ciperText).decrypt();
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
