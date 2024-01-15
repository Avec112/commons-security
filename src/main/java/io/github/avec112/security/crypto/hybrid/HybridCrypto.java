package io.github.avec112.security.crypto.hybrid;

import io.github.avec112.security.crypto.aes.AesCipher;
import io.github.avec112.security.crypto.aes.EncryptionMode;
import io.github.avec112.security.crypto.aes.EncryptionStrength;
import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.error.*;
import io.github.avec112.security.crypto.error.*;
import io.github.avec112.security.crypto.random.RandomUtils;
import io.github.avec112.security.crypto.rsa.RsaCipher;
import io.github.avec112.security.crypto.validate.Validate;

import java.security.PrivateKey;
import java.security.PublicKey;

public class HybridCrypto {

    private HybridCrypto() {
    }

    public static EncryptBuilder encryptionBuilder() {
        return new EncryptBuilder();
    }

    public static DecryptBuilder decryptionBuilder() {
        return new DecryptBuilder();
    }

    public static class EncryptBuilder {
        private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
        private EncryptionMode encryptionMode = EncryptionMode.GCM;

        private String plainText;
        private PublicKey publicKey;

        private EncryptBuilder() {
        }

        public EncryptBuilder key(PublicKey publicKey) {
            Validate.nonNull(publicKey, MissingPublicKeyException::new);
            this.publicKey = publicKey;
            return this;
        }

        public EncryptBuilder plainText(String plainText) {
            Validate.nonBlank(plainText, MissingPlainTextException::new);
            this.plainText = plainText;
            return this;
        }

        public HybridEncryptionResult build() throws Exception {
            Validate.nonNull(publicKey, MissingPublicKeyException::new);
            Validate.nonBlank(plainText, MissingPlainTextException::new);


            final String randomPassword = RandomUtils.randomString(20);
            final String rsaEncryptedKey = rsaEncryptedKey(publicKey, randomPassword);
            final String cipherText = new AesCipher.Builder(new Password(randomPassword))
                    .withMode(encryptionMode)
                    .withStrength(encryptionStrength)
                    .encrypt(plainText);

            return new HybridEncryptionResult(cipherText, rsaEncryptedKey, encryptionMode, encryptionStrength);
        }


        public EncryptBuilder optional(EncryptionMode encryptionMode) {
            Validate.nonNull(encryptionMode, "encryptionMode");
            this.encryptionMode = encryptionMode;
            return this;
        }

        public EncryptBuilder optional(EncryptionStrength encryptionStrength) {
            Validate.nonNull(encryptionStrength, "encryptionStrength");
            this.encryptionStrength = encryptionStrength;
            return this;
        }

        private String rsaEncryptedKey(PublicKey publicKey, String randomPassword) throws Exception {
            RsaCipher rsaCipher = new RsaCipher();
            final CipherText rsaEncryptedKey = rsaCipher.encrypt(new PlainText(randomPassword), publicKey);
            return rsaEncryptedKey.getValue();

        }

    }


    public static class DecryptBuilder {

        private EncryptionStrength encryptionStrength = EncryptionStrength.BIT_128;
        private EncryptionMode encryptionMode = EncryptionMode.GCM;

        private String encryptedSymmetricalKey;
        private String cipherText;

        private PrivateKey privateKey;

        private DecryptBuilder() {
        }

        public DecryptBuilder key(PrivateKey privateKey) {
            Validate.nonNull(privateKey, MissingPrivateKeyException::new);
            this.privateKey = privateKey;
            return this;
        }

        public DecryptBuilder encryptedSymmetricalKey(String encryptedSymmetricalKey) {
            Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new);
            this.encryptedSymmetricalKey = encryptedSymmetricalKey;
            return this;
        }

        public DecryptBuilder cipherText(String cipherText) {
            Validate.nonBlank(cipherText, MissingCipherTextException::new);
            this.cipherText = cipherText;
            return this;
        }

        public String build() throws Exception {
            Validate.all(
                    () -> Validate.nonNull(privateKey, MissingPrivateKeyException::new),
                    () -> Validate.nonBlank(encryptedSymmetricalKey, MissingEncryptedSymmetricalKeyException::new),
                    () -> Validate.nonBlank(cipherText, MissingCipherTextException::new)
            );

            final RsaCipher rsaCipher = new RsaCipher();
            final PlainText symKey = rsaCipher.decrypt(new CipherText(encryptedSymmetricalKey), privateKey);
            return new AesCipher.Builder(symKey.getValue())
                    .withMode(encryptionMode)
                    .withStrength(encryptionStrength)
                    .decrypt(cipherText);
        }

        public DecryptBuilder optional(EncryptionMode encryptionMode) {
            Validate.nonNull(encryptionMode, "encryptionMode");
            this.encryptionMode = encryptionMode;
            return this;
        }

        public DecryptBuilder optional(EncryptionStrength encryptionStrength) {
            Validate.nonNull(encryptionStrength, "encryptionStrength");
            this.encryptionStrength = encryptionStrength;
            return this;
        }

    }

}
