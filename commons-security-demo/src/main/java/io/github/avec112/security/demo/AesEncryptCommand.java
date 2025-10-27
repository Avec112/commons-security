package io.github.avec112.security.demo;

import com.github.avec112.security.crypto.aes.AesEncryptor;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.error.BadCipherConfigurationException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Demonstrates AES-GCM encryption from commons-security-core.
 */
@Command(
        name = "aes",
        description = "Encrypts text using AES-GCM with PBKDF2-derived key."
)
public class AesEncryptCommand implements Runnable {
    @Option(names = "--text", required = true, description = "The plaintext to encrypt.")
    private String text;

    @Option(names = "--password", required = true, description = "Password used to derive the encryption key.")
    private String password;

    @Override
    public void run() {
        try {
            PlainText plainText = new PlainText(text);
            Password pw = new Password(password);
//        CipherText cipherText = CryptoUtils.aesEncrypt(plainText, pw);
            CipherText cipherText = AesEncryptor.withPasswordAndText(pw, plainText).encrypt();
            System.out.println("Encrypted (Base64): " + cipherText.getValue());
        } catch (BadCipherConfigurationException e) {
            throw new CommandLine.ExecutionException(new CommandLine(this), "Encryption failed: " + e.getMessage());
        }
    }
}
