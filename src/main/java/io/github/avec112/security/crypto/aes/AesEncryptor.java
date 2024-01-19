package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.encoding.EncodingUtils;
import lombok.Getter;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Getter
public class AesEncryptor {

    private final Password password;
    private final PlainText plainText;
    private static final int SALT_LENGTH_BYTE = 16;
    private EncryptionMode mode = EncryptionMode.GCM; // default value
    private EncryptionStrength strength = EncryptionStrength.BIT_256; // default value

    private AesEncryptor(Password password, PlainText plainText) {
        this.password = password;
        this.plainText = plainText;
    }

    public static AesEncryptor withPasswordAndText(Password password, PlainText plainText) {
        Validate.notNull(password, "Password cannot be null");
        Validate.notNull(plainText, "PlainText cannot be null");
        Validate.notBlank(password.getValue(), "Password cannot be blank");
        Validate.notBlank(plainText.getValue(), "PlainText cannot be blank");

        return new AesEncryptor(password, plainText);
    }

    public AesEncryptor withMode(EncryptionMode mode) {
        Validate.notNull(mode, "Encryption mode cannot be null");
        this.mode = mode;

        return this; // for chaining
    }

    public AesEncryptor withStrength(EncryptionStrength strength) {
        Validate.notNull(strength, "Encryption strength cannot be null");
        this.strength = strength;

        return this; // for chaining
    }

    public CipherText encrypt() throws BadCipherConfigurationException {
        try {

            final byte[] cipherText = encryptPlainText(plainText, password);
            final String cipherTextEncoded = EncodingUtils.base64Encode(cipherText);
            return new CipherText(cipherTextEncoded);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e);
        }
    }

    private byte[] encryptPlainText(PlainText plainText, Password password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] salt = AesCipherUtils.getRandomNonce(SALT_LENGTH_BYTE);
        byte[] iv = AesCipherUtils.getRandomNonce(getMode().getIvLength());

        Charset encoding = StandardCharsets.UTF_8;
        int encryptionMode = Cipher.ENCRYPT_MODE;

        Cipher cipher = AesCipherUtils.createCipher(password, salt, iv, encryptionMode, getMode(), getStrength().getLength());
        byte[] cText = cipher.doFinal(plainText.getValue().getBytes(encoding));

        return ByteBuffer.allocate(iv.length + salt.length + cText.length)
                .put(iv)
                .put(salt)
                .put(cText)
                .array();
    }
}
