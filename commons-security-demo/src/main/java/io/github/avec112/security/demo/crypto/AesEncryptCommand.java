package io.github.avec112.security.demo.crypto;

import io.github.avec112.security.crypto.aes.AesEncryptor;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Demonstrates AES-GCM encryption from commons-security-core.
 */
@Command(
        name = "aes-encrypt",
        description = "Encrypts text using AES-GCM with PBKDF2-derived key.",
        mixinStandardHelpOptions = true
)
public class AesEncryptCommand implements Runnable {
    @Option(names = {"--text", "-t"}, required = true, description = "The plaintext to encrypt.")
    private String text;

    @Option(names = {"--password", "-p"}, required = true, description = "Password used to derive the encryption key.")
    private String password;

    @Override
    public void run() {
        try {
            PlainText plainText = new PlainText(text);
            Password pw = new Password(password);
            // Alternative CryptoUtils.aesEncrypt(plainText, pw);
            CipherText cipherText = AesEncryptor.withPasswordAndText(pw, plainText).encrypt();
            System.out.println("Encrypted (Base64): " + cipherText.getValue());
        } catch (BadCipherConfigurationException e) {
            throw new CommandLine.ExecutionException(new CommandLine(this), "Encryption failed: " + e.getMessage());
        }
    }
}
