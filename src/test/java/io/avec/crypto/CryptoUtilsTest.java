package io.avec.crypto;

import io.avec.crypto.domain.CipherText;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import io.avec.crypto.rsa.KeySize;
import io.avec.crypto.rsa.KeyUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoUtilsTest {

    @Test
    void aesEncryptAndDecrypt() throws Exception {
        final PlainText plainTextExpected = new PlainText("TEst");
        final Password password = new Password("Password");

        final CipherText cipherText = CryptoUtils.aesEncrypt(plainTextExpected, password);
        final PlainText plainText = CryptoUtils.aesDecrypt(cipherText, password);

        assertEquals(plainTextExpected, plainText);
    }

    @Test
    void aesDecrypt() throws Exception {
        final PlainText plainTextExpected = new PlainText("TEst");
        final Password password = new Password("Password");
        final CipherText cipherText = new CipherText("lZu3cheVaQPY0qqLnsui8dytHNDC6fY9nt12yWHBCZFdwOl+zOZchXmUXC71b7uq");

        final PlainText plainText = CryptoUtils.aesDecrypt(cipherText, password);

        assertEquals(plainTextExpected, plainText);
    }

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void rsaEncryptAndDecrypt(KeySize keySize) throws Exception {
        final PlainText plainTextExpected = new PlainText("Some text");

        final KeyPair keyPair = KeyUtils.generateKeyPair(keySize);

        final CipherText cipherText = CryptoUtils.rsaEncrypt(plainTextExpected, keyPair.getPublic());
        final PlainText plainText = CryptoUtils.rsaDecrypt(cipherText, keyPair.getPrivate());

        assertEquals(plainTextExpected, plainText);
    }

    @Test
    void shamirSplit() {
        final PlainText plainTextExpected = new PlainText("Shamirs Secret Shared");
        final List<Password> passwords = CryptoUtils.shamirSplit(plainTextExpected, 5, 3);
        final PlainText plainText = CryptoUtils.shamirJoin(passwords.get(1), passwords.get(3), passwords.get(2));

        assertEquals(plainTextExpected, plainText);
    }

    @ParameterizedTest
    @CsvSource({
            "MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, MitFSUdpcmpuUi9qUDVFaDhnK3k4MFo5a2ZrUjhl, MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv", // 1, 2, 3
            "MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, NCtMM0grSlJGUDhWWEFua0Zxc3E3K1kxUUUwYzNJ, NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr", // 1, 4, 5
            "MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv, NCtMM0grSlJGUDhWWEFua0Zxc3E3K1kxUUUwYzNJ, NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr", // 3, 4, 5
            "NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr, MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv", // 5, 1, 3
    })
    void shamirJoin(Password pass1, Password pass2, Password pass3) {
        assertEquals("Shamirs Secret Shared", CryptoUtils.shamirJoin(pass1, pass2, pass3).getValue());
    }
}