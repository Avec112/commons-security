package com.github.avec112.security.crypto;

import com.github.avec112.security.crypto.aes.AesDecryptor;
import com.github.avec112.security.crypto.aes.AesEncryptor;
import com.github.avec112.security.crypto.aes.EncryptionMode;
import com.github.avec112.security.crypto.aes.EncryptionStrength;
import com.github.avec112.security.crypto.digest.DigestUtils;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import com.github.avec112.security.crypto.ecc.EccCurve;
import com.github.avec112.security.crypto.ecc.EciesCipher;
import com.github.avec112.security.crypto.error.BadCipherConfigurationException;
import com.github.avec112.security.crypto.hybrid.HybridEncryptionResult;
import com.github.avec112.security.crypto.rsa.RsaCipher;
import com.github.avec112.security.crypto.shamir.Secret;
import com.github.avec112.security.crypto.shamir.Share;
import com.github.avec112.security.crypto.shamir.Shares;
import com.github.avec112.security.crypto.sign.SignatureUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.crypto.BadPaddingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
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

    // ========== Digest Tests ==========

    @Test
    void digest_shouldReturnByteArray() throws Exception {
        final String data = "Test data for digest";
        final byte[] digest = CryptoUtils.digest(data);

        assertThat(digest).isNotNull().isNotEmpty();
    }

    @Test
    void digest_shouldMatchDirectDigestUtilsCall() throws Exception {
        final String data = "Consistency test data";

        final byte[] digestFromUtils = CryptoUtils.digest(data);
        final byte[] digestFromDirectCall = DigestUtils.digest(data);

        assertThat(digestFromUtils).isEqualTo(digestFromDirectCall);
    }

    @Test
    void base64Digest_shouldReturnBase64EncodedString() throws Exception {
        final String data = "Test data for base64 digest";
        final String digest = CryptoUtils.base64Digest(data);

        assertThat(digest).isNotNull().isNotEmpty();
        // Base64 strings should match pattern
        assertThat(digest).matches("^[A-Za-z0-9+/]+=*$");
    }

    @Test
    void hexDigest_shouldReturnHexEncodedString() throws Exception {
        final String data = "Test data for hex digest";
        final String digest = CryptoUtils.hexDigest(data);

        assertThat(digest).isNotNull().isNotEmpty();
        // Hex strings should only contain 0-9, a-f characters
        assertThat(digest).matches("^[0-9a-f]+$");
    }

    // ========== Signature Tests ==========

    @Test
    void sign_shouldCreateValidSignature() throws Exception {
        final String data = "Data to sign";
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate());

        assertThat(signature).isNotNull().isNotEmpty();
    }

    @Test
    void verify_shouldReturnTrueForValidSignature() throws Exception {
        final String data = "Data to sign and verify";
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final byte[] signature = CryptoUtils.sign(data, keyPair.getPrivate());
        final boolean isValid = CryptoUtils.verify(signature, data, keyPair.getPublic());

        assertThat(isValid).isTrue();
    }

    @Test
    void verify_shouldReturnFalseForTamperedData() throws Exception {
        final String originalData = "Original data";
        final String tamperedData = "Tampered data";
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final byte[] signature = CryptoUtils.sign(originalData, keyPair.getPrivate());
        final boolean isValid = CryptoUtils.verify(signature, tamperedData, keyPair.getPublic());

        assertThat(isValid).isFalse();
    }

    @Test
    void verify_shouldReturnFalseForWrongPublicKey() throws Exception {
        final String data = "Data to sign";
        final KeyPair keyPair1 = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);
        final KeyPair keyPair2 = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final byte[] signature = CryptoUtils.sign(data, keyPair1.getPrivate());
        final boolean isValid = CryptoUtils.verify(signature, data, keyPair2.getPublic());

        assertThat(isValid).isFalse();
    }

    @Test
    void signAndVerify_shouldMatchDirectSignatureUtilsCall() throws Exception {
        final String data = "Consistency check data";
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final byte[] signatureFromUtils = CryptoUtils.sign(data, keyPair.getPrivate());
        final byte[] signatureFromDirect = SignatureUtils.sign(data, keyPair.getPrivate());

        // Both should verify successfully
        assertThat(CryptoUtils.verify(signatureFromUtils, data, keyPair.getPublic())).isTrue();
        assertThat(SignatureUtils.verify(signatureFromDirect, data, keyPair.getPublic())).isTrue();

        // Cross-verification should work
        assertThat(CryptoUtils.verify(signatureFromDirect, data, keyPair.getPublic())).isTrue();
        assertThat(SignatureUtils.verify(signatureFromUtils, data, keyPair.getPublic())).isTrue();
    }

    // ========== Ed25519 Signature Tests ==========

    @Test
    void signAndVerifyEd25519() throws Exception {
        final String data = "Ed25519 facade test";
        final KeyPair keyPair = KeyUtils.generateEd25519KeyPair();

        final byte[] signature = CryptoUtils.signEd25519(data, keyPair.getPrivate());
        final boolean isValid = CryptoUtils.verifyEd25519(signature, data, keyPair.getPublic());

        assertThat(isValid).isTrue();
    }

    @Test
    void compareEd25519WithSignatureUtils() throws Exception {
        final String data = "Ed25519 interoperability test";
        final KeyPair keyPair = KeyUtils.generateEd25519KeyPair();

        // Sign with both CryptoUtils and SignatureUtils
        final byte[] signatureFromUtils = CryptoUtils.signEd25519(data, keyPair.getPrivate());
        final byte[] signatureFromDirect = SignatureUtils.signEd25519(data, keyPair.getPrivate());

        // Cross-verification should work
        assertThat(CryptoUtils.verifyEd25519(signatureFromDirect, data, keyPair.getPublic())).isTrue();
        assertThat(SignatureUtils.verifyEd25519(signatureFromUtils, data, keyPair.getPublic())).isTrue();
    }

    // ========== ECDSA Signature Tests ==========

    @Test
    void signAndVerifyEcdsa() throws Exception {
        final String data = "ECDSA facade test";
        final KeyPair keyPair = KeyUtils.generateSecp256r1KeyPair();

        final byte[] signature = CryptoUtils.signEcdsa(data, keyPair.getPrivate());
        final boolean isValid = CryptoUtils.verifyEcdsa(signature, data, keyPair.getPublic());

        assertThat(isValid).isTrue();
    }

    @Test
    void compareEcdsaWithSignatureUtils() throws Exception {
        final String data = "ECDSA interoperability test";
        final KeyPair keyPair = KeyUtils.generateSecp384r1KeyPair();

        // Sign with both CryptoUtils and SignatureUtils
        final byte[] signatureFromUtils = CryptoUtils.signEcdsa(data, keyPair.getPrivate());
        final byte[] signatureFromDirect = SignatureUtils.signEcdsa(data, keyPair.getPrivate());

        // Cross-verification should work
        assertThat(CryptoUtils.verifyEcdsa(signatureFromDirect, data, keyPair.getPublic())).isTrue();
        assertThat(SignatureUtils.verifyEcdsa(signatureFromUtils, data, keyPair.getPublic())).isTrue();
    }

    // ========== Hybrid Encryption Tests ==========

    @Test
    void hybridEncrypt_shouldReturnValidResult() throws Exception {
        final PlainText plainText = new PlainText("Sensitive hybrid data");
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final HybridEncryptionResult result = CryptoUtils.hybridEncrypt(plainText, keyPair.getPublic());

        assertThat(result).isNotNull();
        assertThat(result.getCipherText()).isNotNull();
        assertThat(result.getEncryptedKey()).isNotNull().isNotEmpty();
        assertThat(result.getAesEncryptionMode()).isNotNull();
        assertThat(result.getAesEncryptionStrength()).isNotNull();
    }

    @Test
    void hybridDecrypt_shouldRecoverOriginalPlaintext() throws Exception {
        final PlainText expected = new PlainText("Hybrid encryption test data");
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final HybridEncryptionResult encrypted = CryptoUtils.hybridEncrypt(expected, keyPair.getPublic());
        final PlainText decrypted = CryptoUtils.hybridDecrypt(encrypted, keyPair.getPrivate());

        assertEquals(expected, decrypted);
    }

    @Test
    void hybridEncryptionRoundTrip_withLargeData() throws Exception {
        // RSA can only encrypt small data, but hybrid encryption should handle larger data
        final String largeData = "A".repeat(10000); // 10KB of data
        final PlainText expected = new PlainText(largeData);
        final KeyPair keyPair = KeyUtils.generateRsaKeyPair(KeySize.BIT_2048);

        final HybridEncryptionResult encrypted = CryptoUtils.hybridEncrypt(expected, keyPair.getPublic());
        final PlainText decrypted = CryptoUtils.hybridDecrypt(encrypted, keyPair.getPrivate());

        assertEquals(expected, decrypted);
    }

    // ========== Password Encoding Tests ==========

    @Test
    void encodePassword_shouldReturnEncodedString() {
        final String rawPassword = "MySecurePassword123!";

        final String encoded = CryptoUtils.encodePassword(rawPassword);

        assertThat(encoded).isNotNull().isNotEmpty();
        assertThat(encoded).isNotEqualTo(rawPassword);
    }

    @Test
    void matchesPassword_shouldReturnTrueForCorrectPassword() {
        final String rawPassword = "MySecurePassword123!";
        final String encoded = CryptoUtils.encodePassword(rawPassword);

        final boolean matches = CryptoUtils.matchesPassword(rawPassword, encoded);

        assertThat(matches).isTrue();
    }

    @Test
    void matchesPassword_shouldReturnFalseForIncorrectPassword() {
        final String correctPassword = "CorrectPassword123!";
        final String wrongPassword = "WrongPassword456!";
        final String encoded = CryptoUtils.encodePassword(correctPassword);

        final boolean matches = CryptoUtils.matchesPassword(wrongPassword, encoded);

        assertThat(matches).isFalse();
    }

    @Test
    void matchesPassword_shouldAutoDetectArgon2() {
        final String rawPassword = "MySecurePassword123!";
        final String argon2Encoded = CryptoUtils.encodePassword(rawPassword);

        final boolean matches = CryptoUtils.matchesPassword(rawPassword, argon2Encoded);

        assertThat(matches).isTrue();
    }

    @Test
    void matchesPassword_shouldAutoDetectBcrypt() {
        final String rawPassword = "Password";
        final String bcryptEncoded = "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK";

        final boolean matches = CryptoUtils.matchesPassword(rawPassword, bcryptEncoded);

        assertThat(matches).isTrue();
    }

    @Test
    void matchesPassword_shouldAutoDetectScrypt() {
        final String rawPassword = "Password";
        final String scryptEncoded = "{scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=";

        final boolean matches = CryptoUtils.matchesPassword(rawPassword, scryptEncoded);

        assertThat(matches).isTrue();
    }

    @Test
    void needsPasswordUpgrade_shouldReturnTrueForNonArgon2() {
        final String bcryptPassword = "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK";

        final boolean needsUpgrade = CryptoUtils.needsPasswordUpgrade(bcryptPassword);

        assertThat(needsUpgrade).isTrue();
    }

    @Test
    void needsPasswordUpgrade_shouldReturnFalseForArgon2() {
        final String rawPassword = "MyPassword123";
        final String argon2Password = CryptoUtils.encodePassword(rawPassword);

        final boolean needsUpgrade = CryptoUtils.needsPasswordUpgrade(argon2Password);

        assertThat(needsUpgrade).isFalse();
    }

    @Test
    void upgradePassword_shouldUpgradeFromBcryptToArgon2() {
        final String rawPassword = "Password";
        final String bcryptPassword = "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK";

        final String upgradedPassword = CryptoUtils.upgradePassword(rawPassword, bcryptPassword);

        assertThat(upgradedPassword).startsWith("{argon2}");
        assertThat(CryptoUtils.matchesPassword(rawPassword, upgradedPassword)).isTrue();
        assertThat(CryptoUtils.needsPasswordUpgrade(upgradedPassword)).isFalse();
    }

    @Test
    void getVersion_shouldMatchPomXmlVersion() throws Exception {
        // Read version from pom.xml
        String pomVersion = readVersionFromPom();

        // Assert that CryptoUtils.getVersion() matches pom.xml version
        assertThat(CryptoUtils.getVersion())
                .as("CryptoUtils.VERSION should match the version in pom.xml")
                .isEqualTo(pomVersion);
    }

    // ========== ECIES Encryption Tests ==========

    @Test
    void eciesEncryptAndDecrypt() throws Exception {
        final String plainTextExpected = "ECIES facade test message";
        final KeyPair keyPair = KeyUtils.generateEcKeyPair(EccCurve.SECP256R1);

        final byte[] ciphertext = CryptoUtils.eciesEncrypt(plainTextExpected, keyPair.getPublic());
        final String decrypted = CryptoUtils.eciesDecrypt(ciphertext, keyPair.getPrivate());

        assertEquals(plainTextExpected, decrypted);
    }

    @Test
    void compareEciesCipherWithCryptoUtils() throws Exception {
        final String expected = "ECIES interoperability test";
        final KeyPair keyPair = KeyUtils.generateEcKeyPair(EccCurve.SECP256R1);

        // Encrypt directly with EciesCipher
        final byte[] directCipher = EciesCipher.encrypt(expected, keyPair.getPublic());

        // Encrypt via CryptoUtils
        final byte[] utilCipher = CryptoUtils.eciesEncrypt(expected, keyPair.getPublic());

        // Cross-decrypt both
        final String decryptedFromDirect = CryptoUtils.eciesDecrypt(directCipher, keyPair.getPrivate());
        final String decryptedFromUtils = EciesCipher.decrypt(utilCipher, keyPair.getPrivate());

        assertEquals(expected, decryptedFromDirect,
                "CryptoUtils.eciesDecrypt should correctly decrypt ciphertext from EciesCipher.encrypt");

        assertEquals(expected, decryptedFromUtils,
                "EciesCipher.decrypt should correctly decrypt ciphertext from CryptoUtils.eciesEncrypt");
    }

    private String readVersionFromPom() throws Exception {
        File pomFile = new File("pom.xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(pomFile);

        NodeList versionNodes = doc.getElementsByTagName("version");
        if (versionNodes.getLength() > 0) {
            return versionNodes.item(0).getTextContent();
        }

        throw new IllegalStateException("Could not find version in pom.xml");
    }
}