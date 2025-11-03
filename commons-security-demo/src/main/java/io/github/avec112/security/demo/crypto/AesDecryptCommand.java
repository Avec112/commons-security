package io.github.avec112.security.demo.crypto;

import io.github.avec112.security.crypto.aes.AesDecryptor;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.crypto.error.BadCipherTextException;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Demonstrates AES-GCM decryption from commons-security-core.
 */
@Command(
        name = "aes-decrypt",
        description = "Decrypts cipher using AES-GCM with PBKDF2-derived key.",
        mixinStandardHelpOptions = true
)
public class AesDecryptCommand implements Runnable {
    @Option(names = {"--cipher", "-c"}, required = true, description = "The ciphertext to decrypt (Base64).")
    private String cipher;

    @Option(names = {"--password", "-p"}, required = true, description = "Password used to derive the encryption key.")
    private String password;

    @Override
    public void run() {
        try {
            CipherText cipherText = new CipherText(cipher);
            Password pw = new Password(password);
            // Alternative CryptoUtils.aesDecrypt(cipherText, pw);
            PlainText plainText = AesDecryptor.withPasswordAndCipherText(pw, cipherText).decrypt();
            System.out.println("Decrypted: " + plainText.getValue());
        } catch (BadCipherConfigurationException | BadCipherTextException e) {
            throw new CommandLine.ExecutionException(new CommandLine(this), "Decryption failed: " + e.getMessage());
        }
    }
}
