package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.CipherText;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import io.github.avec112.security.crypto.error.BadCipherConfigurationException;
import io.github.avec112.security.crypto.error.BadCipherTextException;
import io.github.avec112.security.encoding.EncodingUtils;
import lombok.Getter;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Getter
public class AesDecryptor {
    private final Password password;
    private final CipherText cipherText;

    private static final int SALT_LENGTH_BYTE = 16;
    private EncryptionMode mode = EncryptionMode.GCM;
    private EncryptionStrength strength = EncryptionStrength.BIT_256;

    private AesDecryptor(Password password, CipherText cipherText) {
        this.password = password;
        this.cipherText = cipherText;
    }

    public static AesDecryptor withPasswordAndCipherText(Password password, CipherText cipherText) {
        Validate.notNull(password, "Password cannot be null");
        Validate.notNull(cipherText, "CipherText cannot be null");
        Validate.notBlank(password.getValue(), "Password cannot be blank");
        Validate.notBlank(cipherText.getValue(), "CipherText cannot be blank");

        return new AesDecryptor(password, cipherText);
    }

    public AesDecryptor withMode(EncryptionMode mode) {
        Validate.notNull(mode, "Mode cannot be null");
        this.mode = mode;
        return this;
    }

    public AesDecryptor withStrength(EncryptionStrength strength) {
        Validate.notNull(strength, "Strength cannot be null");
        this.strength = strength;
        return this;
    }

    public PlainText decrypt() throws BadCipherConfigurationException, BadCipherTextException {
        try {
            final byte[] bytes = decryptCipherText(cipherText, password);
            return new PlainText(new String(bytes));
        } catch (BufferUnderflowException e) {
            throw new BadCipherTextException("Please provide valid cipher text");
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new BadCipherConfigurationException(e);
        }
    }

    private byte[] decryptCipherText(CipherText cipherText, Password password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        final String cipherTextEncoded = cipherText.getValue();
        final byte[] cipherTextBytes = EncodingUtils.base64Decode(cipherTextEncoded);

        ByteBuffer buffer = ByteBuffer.wrap(cipherTextBytes); // IV+SALT+CIPHERTEXT

        // 12 bytes GCM vs 16 bytes CTR
        int ivLengthByte = getMode().getIvLength();
        byte[] iv = new byte[ivLengthByte];
        buffer.get(iv);

        // 16 bytes salt
        byte[] salt = new byte[SALT_LENGTH_BYTE];
        buffer.get(salt);

        byte[] cText = new byte[buffer.remaining()];
        buffer.get(cText);

        Cipher cipher = AesCipherUtils.createCipher(password, salt, iv, Cipher.DECRYPT_MODE, getMode(), getStrength().getLength());
        return cipher.doFinal(cText);
    }

}
