package io.github.avec112.security.crypto.rsa;

import io.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.PlainText;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

public class RsaCipherTest extends BouncyCastleProviderInitializer {

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void encryptAndDecrypt(KeySize keySize) throws Exception {
        // Arrange
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize.getKeySize());
        KeyPair keyPair = keyGen.generateKeyPair();

        RsaCipher cipher = new RsaCipher();
        PlainText expected = new PlainText("Secret message for RSA");

        // Act
        CipherText encrypted = cipher.encrypt(expected, keyPair.getPublic());
        assertNotEquals(expected.getValue(), encrypted.getValue(), "Cipher text must differ from plain text");

        PlainText decrypted = cipher.decrypt(encrypted, keyPair.getPrivate());

        // Assert
        assertEquals(expected, decrypted, "Decrypted text must equal original plain text");
    }

    @Test
    void decryptFailsWithWrongPrivateKey() throws Exception {
        // Arrange
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KeySize.BIT_2048.getKeySize());
        KeyPair correct = keyGen.generateKeyPair();
        KeyPair wrong = keyGen.generateKeyPair();

        RsaCipher cipher = new RsaCipher();
        PlainText expected = new PlainText("Integrity check");

        CipherText encrypted = cipher.encrypt(expected, correct.getPublic());

        // Act & Assert
        assertThrows(Exception.class, () -> cipher.decrypt(encrypted, wrong.getPrivate()),
                "Decryption with wrong key should fail");
    }

    @Test
    void decryptFailsWithCorruptedCipherText() throws Exception {
        // Arrange
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KeySize.BIT_2048.getKeySize());
        KeyPair keyPair = keyGen.generateKeyPair();

        RsaCipher cipher = new RsaCipher();
        PlainText expected = new PlainText("Corruption test");
        CipherText encrypted = cipher.encrypt(expected, keyPair.getPublic());

        // Corrupt the base64 value a bit
        String corrupted = encrypted.getValue().substring(0, encrypted.getValue().length() - 4) + "ABCD";

        // Act
        assertThrows(Exception.class, () -> cipher.decrypt(new CipherText(corrupted), keyPair.getPrivate()),
                "Decrypting corrupted cipher text should throw exception");
    }

}