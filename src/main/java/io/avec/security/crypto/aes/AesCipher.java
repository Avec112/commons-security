package io.avec.security.crypto.aes;

import io.avec.security.crypto.domain.CipherText;
import io.avec.security.crypto.domain.Password;
import io.avec.security.crypto.domain.PlainText;
import io.avec.security.crypto.error.BadCipherConfigurationException;
import io.avec.security.crypto.error.BadCipherTextException;
import io.avec.security.encoding.EncodingUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Slf4j
@Getter
@Setter
public class AesCipher  {

    private static final int SALT_LENGTH_BYTE = 16;
    private EncryptionMode algorithm = EncryptionMode.GCM;
    private EncryptionStrength keyLength = EncryptionStrength.BIT_256;

    private AesCipher() {
    }

    public CipherText encrypt(PlainText plainText, Password password) throws Exception {

        log.debug("{}@{}", getAlgorithm(), getKeyLength().getLength());
        log.debug("plainText: {}", plainText.getValue());

        // 16 bytes salt
        byte[] salt = AesCipherUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // 12 bytes GCM vs 16 bytes CTR
        byte[] iv = AesCipherUtils.getRandomNonce(getAlgorithm().getIvLength());

        // secret key from password
        Key key = AesCipherUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, getKeyLength());

        Cipher cipher = Cipher.getInstance(getAlgorithm().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key, getAlgorithm().getAlgorithmParameterSpec(iv));
        byte [] cText = cipher.doFinal(plainText.getValue().getBytes(StandardCharsets.UTF_8));

        // Concat IV+SALT+CIPHERTEXT
        final byte[] cipherText = ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
        final String cipherTextEncoded = EncodingUtils.base64Encode(cipherText);
        log.debug("cipherText: {}", cipherTextEncoded);
        return new CipherText(cipherTextEncoded);
    }

    public PlainText decrypt(CipherText cipherText, Password password) throws BadCipherTextException, BadCipherConfigurationException {
        try {
            log.debug("{}@{}", getAlgorithm(), getKeyLength().getLength());
            final String cipherTextEncoded = cipherText.getValue();
            log.debug("cipherText: {}", cipherTextEncoded);
            final byte[] cipherTextBytes = EncodingUtils.base64Decode(cipherTextEncoded);

            ByteBuffer bb = ByteBuffer.wrap(cipherTextBytes); // IV+SALT+CIPHERTEXT

            // 12 bytes GCM vs 16 bytes CTR
            int ivLengthByte = getAlgorithm().getIvLength();
            byte[] iv = new byte[ivLengthByte];
            bb.get(iv);

            // 16 bytes salt
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            bb.get(salt);

            byte[] cText = new byte[bb.remaining()];
            bb.get(cText);

            // secret key from password
            Key key = AesCipherUtils.getAESKeyFromPassword(password.getValue().toCharArray(), salt, getKeyLength());

            Cipher cipher = Cipher.getInstance(getAlgorithm().getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key, getAlgorithm().getAlgorithmParameterSpec(iv));
            final byte[] bytes = cipher.doFinal(cText);
            log.debug("plainText: {}", new String(bytes));
            return new PlainText(new String(bytes));
        } catch (BufferUnderflowException e) {
            throw new BadCipherTextException("Please provide valid cipher text");
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e.getMessage());
        }


    }

    public static Builder withPassword(Password password) {
        return new Builder(password);
    }

    public static Builder withPassword(String password) {
        return new Builder(password);
    }

    public static class Builder {
        private final Password password;

        private EncryptionMode algorithm;
        private EncryptionStrength keyLength;

        public Builder(Password password) {
            Validate.notNull(password);
            Validate.notBlank(password.getValue());
            this.password = password;
        }

        public Builder(String password) {
            Validate.notBlank(password);
            this.password = new Password(password);
        }

        public Builder withMode(EncryptionMode algorithm) {
            Validate.notNull(algorithm);
            this.algorithm = algorithm;
            return this;
        }

        public Builder withStrength(EncryptionStrength encryptionStrength) {
            Validate.notNull(encryptionStrength);
            this.keyLength = encryptionStrength;
            return this;
        }

        public String encrypt(String plainText) throws Exception {
            return encrypt(new PlainText(plainText)).getValue();
        }

        public CipherText encrypt(PlainText plainText) throws Exception {
            Validate.notNull(plainText);
            Validate.notBlank(plainText.getValue());

            AesCipher aesCipher = new AesCipher();
            if(algorithm != null) {
                aesCipher.setAlgorithm(algorithm);
            }
            if(keyLength != null) {
                aesCipher.setKeyLength(keyLength);
            }

            return aesCipher.encrypt(plainText, password);
        }

        public String decrypt(String cipherText) throws BadCipherConfigurationException, BadCipherTextException {
            Validate.notBlank(cipherText);
            return decrypt(new CipherText(cipherText)).getValue();
        }

        public PlainText decrypt(CipherText cipherText) throws BadCipherConfigurationException, BadCipherTextException {
            Validate.notNull(cipherText);
            Validate.notBlank(cipherText.getValue());
            AesCipher aesCipher = new AesCipher();
            if(algorithm != null) {
                aesCipher.setAlgorithm(algorithm);
            }
            if(keyLength != null) {
                aesCipher.setKeyLength(keyLength);
            }

            return aesCipher.decrypt(cipherText, password);
        }
    }

}
