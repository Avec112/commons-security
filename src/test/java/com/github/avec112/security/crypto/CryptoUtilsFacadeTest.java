package com.github.avec112.security.crypto;

import com.github.avec112.security.crypto.error.BadCipherConfigurationException;
import com.github.avec112.security.crypto.aes.AesDecryptor;
import com.github.avec112.security.crypto.aes.AesEncryptor;
import com.github.avec112.security.crypto.aes.EncryptionMode;
import com.github.avec112.security.crypto.aes.EncryptionStrength;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.rsa.KeySize;
import com.github.avec112.security.crypto.rsa.KeyUtils;
import com.github.avec112.security.crypto.rsa.RsaCipher;
import com.github.avec112.security.crypto.shamir.Secret;
import com.github.avec112.security.crypto.shamir.Share;
import com.github.avec112.security.crypto.shamir.Shares;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.BadPaddingException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Comprehensive test suite for the {@link CryptoUtils} facade.
 *
 * <p>This class verifies functional correctness, interoperability, and exception handling
 * across all major cryptographic components in the commons-security library.</p>
 *
 * <h2>Test coverage</h2>
 * <ul>
 *     <li><b>AES encryption/decryption</b> – Ensures round-trip consistency,
 *         verifies known ciphertexts, and validates proper exception handling
 *         on incorrect passwords.</li>
 *     <li><b>AES interoperability</b> – Confirms {@link CryptoUtils} and
 *         {@link AesEncryptor}/{@link AesDecryptor}
 *         produce compatible results.</li>
 *     <li><b>RSA encryption/decryption</b> – Tests all {@link KeySize}
 *         variants and validates bidirectional interoperability between
 *         {@link CryptoUtils} and {@link RsaCipher}.</li>
 *     <li><b>Shamir's Secret Sharing</b> – Verifies share generation and
 *         reconstruction via {@link CryptoUtils#getShamirShares} and {@link CryptoUtils#getShamirSecret}.</li>
 *     <li><b>Error handling</b> – Confirms that invalid inputs (such as corrupted shares)
 *         correctly propagate exceptions instead of producing undefined results.</li>
 * </ul>
 *
 * <h2>Purpose</h2>
 * <p>The goal of this test class is to ensure internal API alignment between
 * the low-level cryptographic engines (AES, RSA, Shamir) and their unified
 * entry point {@link CryptoUtils}. It acts as an integration test between
 * the core components of the library.</p>
 *
 * <h2>Execution</h2>
 * <ul>
 *     <li>All tests are deterministic except those involving random salt/IVs,
 *         which are validated through functional equality (not ciphertext equality).</li>
 *     <li>RSA key generation tests all configured key sizes to ensure compatibility
 *         with the {@link java.security.KeyPairGenerator} setup and provider configuration.</li>
 * </ul>
 *
 */
class CryptoUtilsFacadeTest {

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

    @Test
    void aesDecryptWithWrongPassword_shouldFail() throws Exception {
        final PlainText plainTextExpected = new PlainText("Sensitive data");
        final Password correctPassword = new Password("CorrectPassword");
        final Password wrongPassword = new Password("WrongPassword");

        final CipherText cipherText = CryptoUtils.aesEncrypt(plainTextExpected, correctPassword);

        // Expect project-specific wrapper exception
        final BadCipherConfigurationException ex =
                Assertions.assertThrows(
                        BadCipherConfigurationException.class,
                        () -> CryptoUtils.aesDecrypt(cipherText, wrongPassword),
                        "Decrypting with the wrong password should fail with a wrapped crypto exception"
                );

        // Optional: verify the root cause
        final Throwable cause = ex.getCause();
        Assertions.assertNotNull(cause, "Wrapped exception should carry the root cause");
        Assertions.assertInstanceOf(BadPaddingException.class, cause, "Root cause should be BadPaddingException (including AEADBadTagException subclass)");
    }

    @Test
    void compareAesEncryptorWithCryptoUtils() throws Exception {
        final PlainText expected = new PlainText("Sensitive comparison test");
        final Password password = new Password("StrongPassword123!");

        final AesEncryptor encryptor = AesEncryptor
                .withPasswordAndText(password, expected)
                .withMode(EncryptionMode.GCM)
                .withStrength(EncryptionStrength.BIT_256);

        final CipherText directCipher = encryptor.encrypt();
        final CipherText utilCipher = CryptoUtils.aesEncrypt(expected, password);

        final PlainText decryptedFromDirect = CryptoUtils.aesDecrypt(directCipher, password);
        final PlainText decryptedFromUtils = AesDecryptor
                .withPasswordAndCipherText(password, utilCipher)
                .withMode(EncryptionMode.GCM)
                .withStrength(EncryptionStrength.BIT_256)
                .decrypt();

        assertEquals(expected, decryptedFromDirect);
        assertEquals(expected, decryptedFromUtils);
    }

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void rsaEncryptAndDecrypt(KeySize keySize) throws Exception {
        final PlainText plainTextExpected = new PlainText("Some text");

        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(keySize);

        final CipherText cipherText = CryptoUtils.rsaEncrypt(plainTextExpected, keyPair.getPublic());
        final PlainText plainText = CryptoUtils.rsaDecrypt(cipherText, keyPair.getPrivate());

        assertEquals(plainTextExpected, plainText);
    }

    @Test
    void compareRsaCipherWithCryptoUtils() throws Exception {
        final PlainText expected = new PlainText("RSA interoperability test");

        // Generate RSA key pair (whatever your KeyUtils implementation supports)
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        // Encrypt directly with RsaCipher
        final RsaCipher rsaCipher = new RsaCipher();
        final CipherText directCipher = rsaCipher.encrypt(expected, keyPair.getPublic());

        // Encrypt via CryptoUtils
        final CipherText utilCipher = CryptoUtils.rsaEncrypt(expected, keyPair.getPublic());

        // Cross-decrypt both
        final PlainText decryptedFromDirect = CryptoUtils.rsaDecrypt(directCipher, keyPair.getPrivate());
        final PlainText decryptedFromUtils = rsaCipher.decrypt(utilCipher, keyPair.getPrivate());

        assertEquals(expected, decryptedFromDirect,
                "CryptoUtils.rsaDecrypt should correctly decrypt ciphertext from RsaCipher.encrypt");

        assertEquals(expected, decryptedFromUtils,
                "RsaCipher.decrypt should correctly decrypt ciphertext from CryptoUtils.rsaEncrypt");
    }

    @Test
    void getShamirShares() {
        final Secret secretExpected = new Secret("Shamirs Secret Shared");
        final Shares shares = CryptoUtils.getShamirShares(secretExpected, 5, 3);
        final Secret secret = CryptoUtils.getShamirSecret(shares.get(1), shares.get(3), shares.get(2));

        assertEquals(secretExpected, secret);
    }

    @ParameterizedTest
    @CsvSource({
            "MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, MitFSUdpcmpuUi9qUDVFaDhnK3k4MFo5a2ZrUjhl, MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv", // 1, 2, 3
            "MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, NCtMM0grSlJGUDhWWEFua0Zxc3E3K1kxUUUwYzNJ, NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr", // 1, 4, 5
            "MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv, NCtMM0grSlJGUDhWWEFua0Zxc3E3K1kxUUUwYzNJ, NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr", // 3, 4, 5
            "NStWNUxadGlLZkNmZ0RUNi9aNDQ2c2N1ekFaSGIr, MStLNHRHL2xxaWk0MlF0STNCTkZSeVF0Q2x4OTVT, MythR0tGUFFvQkJwNDZ3L0dUcWc5bWRtSGJKS1Fv", // 5, 1, 3
    })
    void getShamirSecret(Share share1, Share share2, Share share3) {
        Assertions.assertEquals("Shamirs Secret Shared", CryptoUtils.getShamirSecret(share1, share2, share3).getValue());
    }

    @Test
    void getShamirSecret_withInvalidShare_shouldThrow() {
        final Secret secretExpected = new Secret("Top secret data");
        final Shares shares = CryptoUtils.getShamirShares(secretExpected, 5, 3);

        // Use two valid shares and one deliberately corrupted share
        final Share valid1 = shares.get(0);
        final Share valid2 = shares.get(1);

        // Construct an invalid share (malformed Base64 or wrong format)
        final Share invalid = new Share("corrupted_base64_value");

        Exception ex = Assertions.assertThrows(
                RuntimeException.class, // or your custom type if you have one
                () -> CryptoUtils.getShamirSecret(valid1, valid2, invalid),
                "Expected an exception when one of the shares is invalid"
        );

        // Optional: verify cause chain for debug clarity
        Assertions.assertNotNull(ex.getMessage());
        System.out.println("Expected failure message: " + ex.getMessage());
    }

}