package io.github.avec112.security.crypto;

import io.github.avec112.security.crypto.aes.AesKeySize;
import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.rsa.RsaKeySize;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@code KeyStorageUtil} class.
 * Tests cover storage, loading, and format conversion of cryptographic keys.
 */
@Execution(ExecutionMode.CONCURRENT)
class KeyStorageUtilTest extends BouncyCastleProviderInitializer {

    @TempDir
    Path tempDir;

    // ========== RSA Key Storage Tests ==========

    @Test
    void saveAndLoadPrivateKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Path keyPath = tempDir.resolve("private_key.pem");

        // Act
        KeyStorageUtil.savePrivateKey(keyPair.getPrivate(), keyPath);
        PrivateKey loadedKey = KeyStorageUtil.loadPrivateKey(keyPath, "RSA");

        // Assert
        assertNotNull(loadedKey);
        assertEquals(keyPair.getPrivate().getAlgorithm(), loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void saveAndLoadPublicKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Path keyPath = tempDir.resolve("public_key.pem");

        // Act
        KeyStorageUtil.savePublicKey(keyPair.getPublic(), keyPath);
        PublicKey loadedKey = KeyStorageUtil.loadPublicKey(keyPath, "RSA");

        // Assert
        assertNotNull(loadedKey);
        assertEquals(keyPair.getPublic().getAlgorithm(), loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void savePrivateKeyCreatesPemFormat() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Path keyPath = tempDir.resolve("private_key.pem");

        // Act
        KeyStorageUtil.savePrivateKey(keyPair.getPrivate(), keyPath);
        String content = Files.readString(keyPath);

        // Assert
        assertTrue(content.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(content.contains("-----END PRIVATE KEY-----"));
    }

    @Test
    void savePublicKeyCreatesPemFormat() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Path keyPath = tempDir.resolve("public_key.pem");

        // Act
        KeyStorageUtil.savePublicKey(keyPair.getPublic(), keyPath);
        String content = Files.readString(keyPath);

        // Assert
        assertTrue(content.contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(content.contains("-----END PUBLIC KEY-----"));
    }

    // ========== EC Key Storage Tests ==========

    @Test
    void saveAndLoadEcPrivateKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateSecp256r1KeyPair();
        Path keyPath = tempDir.resolve("ec_private_key.pem");

        // Act
        KeyStorageUtil.savePrivateKey(keyPair.getPrivate(), keyPath);
        PrivateKey loadedKey = KeyStorageUtil.loadPrivateKey(keyPath, "EC");

        // Assert
        assertNotNull(loadedKey);
        assertEquals("EC", loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void saveAndLoadEcPublicKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateSecp256r1KeyPair();
        Path keyPath = tempDir.resolve("ec_public_key.pem");

        // Act
        KeyStorageUtil.savePublicKey(keyPair.getPublic(), keyPath);
        PublicKey loadedKey = KeyStorageUtil.loadPublicKey(keyPath, "EC");

        // Assert
        assertNotNull(loadedKey);
        assertEquals("EC", loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), loadedKey.getEncoded());
    }

    // ========== Ed25519 Key Storage Tests ==========

    @Test
    void saveAndLoadEd25519PrivateKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateEd25519KeyPair();
        Path keyPath = tempDir.resolve("ed25519_private_key.pem");

        // Act
        KeyStorageUtil.savePrivateKey(keyPair.getPrivate(), keyPath);
        PrivateKey loadedKey = KeyStorageUtil.loadPrivateKey(keyPath, "Ed25519");

        // Assert
        assertNotNull(loadedKey);
        assertEquals("Ed25519", loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void saveAndLoadEd25519PublicKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateEd25519KeyPair();
        Path keyPath = tempDir.resolve("ed25519_public_key.pem");

        // Act
        KeyStorageUtil.savePublicKey(keyPair.getPublic(), keyPath);
        PublicKey loadedKey = KeyStorageUtil.loadPublicKey(keyPath, "Ed25519");

        // Assert
        assertNotNull(loadedKey);
        assertEquals("Ed25519", loadedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), loadedKey.getEncoded());
    }

    // ========== AES Key Storage Tests ==========

    @Test
    void saveAndLoadAesKey() throws Exception {
        // Arrange
        SecretKey secretKey = KeyGeneratorUtil.generateAesKey(AesKeySize.BIT_256);
        Path keyPath = tempDir.resolve("aes_key.txt");

        // Act
        KeyStorageUtil.saveAesKey(secretKey, keyPath);
        SecretKey loadedKey = KeyStorageUtil.loadAesKey(keyPath);

        // Assert
        assertNotNull(loadedKey);
        assertEquals("AES", loadedKey.getAlgorithm());
        assertArrayEquals(secretKey.getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void saveAndLoadAesKeyEncrypted() throws Exception {
        // Arrange
        SecretKey secretKey = KeyGeneratorUtil.generateAesKey(AesKeySize.BIT_256);
        Password password = new Password("StrongPassword123!");
        Path keyPath = tempDir.resolve("aes_key_encrypted.txt");

        // Act
        KeyStorageUtil.saveAesKeyEncrypted(secretKey, password, keyPath);
        SecretKey loadedKey = KeyStorageUtil.loadAesKeyEncrypted(keyPath, password);

        // Assert
        assertNotNull(loadedKey);
        assertEquals("AES", loadedKey.getAlgorithm());
        assertArrayEquals(secretKey.getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void loadAesKeyEncryptedWithWrongPasswordThrowsException() throws Exception {
        // Arrange
        SecretKey secretKey = KeyGeneratorUtil.generateAesKey(AesKeySize.BIT_256);
        Password correctPassword = new Password("CorrectPassword123!");
        Password wrongPassword = new Password("WrongPassword456!");
        Path keyPath = tempDir.resolve("aes_key_encrypted.txt");
        KeyStorageUtil.saveAesKeyEncrypted(secretKey, correctPassword, keyPath);

        // Act & Assert
        assertThrows(Exception.class, () ->
            KeyStorageUtil.loadAesKeyEncrypted(keyPath, wrongPassword)
        );
    }

    // ========== PEM Format Conversion Tests ==========

    @Test
    void toPemFormatCreatesCorrectStructure() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        byte[] keyBytes = keyPair.getPublic().getEncoded();

        // Act
        String pem = KeyStorageUtil.toPemFormat(keyBytes, "PUBLIC KEY");

        // Assert
        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"));
        assertTrue(pem.endsWith("-----END PUBLIC KEY-----\n"));
        assertTrue(pem.contains("\n"));

        // Verify 64-character line wrapping (excluding headers/footers)
        String[] lines = pem.split("\n");
        for (int i = 1; i < lines.length - 1; i++) {
            assertTrue(lines[i].length() <= 64,
                "Line " + i + " exceeds 64 characters: " + lines[i].length());
        }
    }

    @Test
    void fromPemFormatExtractsCorrectBytes() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        byte[] originalBytes = keyPair.getPublic().getEncoded();
        String pem = KeyStorageUtil.toPemFormat(originalBytes, "PUBLIC KEY");

        // Act
        byte[] extractedBytes = KeyStorageUtil.fromPemFormat(pem);

        // Assert
        assertArrayEquals(originalBytes, extractedBytes);
    }

    @Test
    void toPemAndFromPemAreReversible() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        byte[] originalBytes = keyPair.getPrivate().getEncoded();

        // Act
        String pem = KeyStorageUtil.toPemFormat(originalBytes, "PRIVATE KEY");
        byte[] extractedBytes = KeyStorageUtil.fromPemFormat(pem);

        // Assert
        assertArrayEquals(originalBytes, extractedBytes);
    }

    // ========== Base64 Export/Import Tests ==========

    @Test
    void exportAndImportPublicKeyAsBase64() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);

        // Act
        String base64Key = KeyStorageUtil.exportPublicKeyAsBase64(keyPair.getPublic());
        PublicKey importedKey = KeyStorageUtil.importPublicKeyFromBase64(base64Key, "RSA");

        // Assert
        assertNotNull(importedKey);
        assertEquals(keyPair.getPublic().getAlgorithm(), importedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), importedKey.getEncoded());
    }

    @Test
    void exportAndImportEcPublicKeyAsBase64() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateSecp256r1KeyPair();

        // Act
        String base64Key = KeyStorageUtil.exportPublicKeyAsBase64(keyPair.getPublic());
        PublicKey importedKey = KeyStorageUtil.importPublicKeyFromBase64(base64Key, "EC");

        // Assert
        assertNotNull(importedKey);
        assertEquals("EC", importedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), importedKey.getEncoded());
    }

    @Test
    void exportAndImportEd25519PublicKeyAsBase64() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateEd25519KeyPair();

        // Act
        String base64Key = KeyStorageUtil.exportPublicKeyAsBase64(keyPair.getPublic());
        PublicKey importedKey = KeyStorageUtil.importPublicKeyFromBase64(base64Key, "Ed25519");

        // Assert
        assertNotNull(importedKey);
        assertEquals("Ed25519", importedKey.getAlgorithm());
        assertArrayEquals(keyPair.getPublic().getEncoded(), importedKey.getEncoded());
    }

    // ========== Key Validation Tests ==========

    @Test
    void isRsaKeySufficientReturnsTrueForValidKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_3072);

        // Act
        boolean isSufficient = KeyStorageUtil.isRsaKeySufficient(keyPair, 2048);

        // Assert
        assertTrue(isSufficient);
    }

    @Test
    void isRsaKeySufficientReturnsFalseForWeakKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);

        // Act
        boolean isSufficient = KeyStorageUtil.isRsaKeySufficient(keyPair, 3072);

        // Assert
        assertFalse(isSufficient);
    }

    @Test
    void isRsaKeySufficientReturnsFalseForNonRsaKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateSecp256r1KeyPair();

        // Act
        boolean isSufficient = KeyStorageUtil.isRsaKeySufficient(keyPair, 2048);

        // Assert
        assertFalse(isSufficient);
    }

    // ========== Key Metadata Tests ==========

    @Test
    void getKeyMetadataForRsaKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);

        // Act
        KeyStorageUtil.KeyMetadata metadata = KeyStorageUtil.getKeyMetadata(keyPair);

        // Assert
        assertNotNull(metadata);
        assertEquals("RSA", metadata.getAlgorithm());
        assertEquals(2048, metadata.getKeySize());
        assertEquals("PKCS#8", metadata.getFormat());
    }

    @Test
    void getKeyMetadataForEcKey() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateSecp256r1KeyPair();

        // Act
        KeyStorageUtil.KeyMetadata metadata = KeyStorageUtil.getKeyMetadata(keyPair);

        // Assert
        assertNotNull(metadata);
        assertEquals("EC", metadata.getAlgorithm());
        assertTrue(metadata.getKeySize() > 0);
        assertEquals("PKCS#8", metadata.getFormat());
    }

    @Test
    void getKeyMetadataForEd25519Key() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateEd25519KeyPair();

        // Act
        KeyStorageUtil.KeyMetadata metadata = KeyStorageUtil.getKeyMetadata(keyPair);

        // Assert
        assertNotNull(metadata);
        assertEquals("Ed25519", metadata.getAlgorithm());
        assertEquals("PKCS#8", metadata.getFormat());
    }

    // ========== Error Handling Tests ==========

    @Test
    void loadPrivateKeyFromNonExistentFileThrowsException() {
        // Arrange
        Path nonExistentPath = tempDir.resolve("non_existent_key.pem");

        // Act & Assert
        assertThrows(Exception.class, () ->
            KeyStorageUtil.loadPrivateKey(nonExistentPath, "RSA")
        );
    }

    @Test
    void loadPublicKeyFromNonExistentFileThrowsException() {
        // Arrange
        Path nonExistentPath = tempDir.resolve("non_existent_key.pem");

        // Act & Assert
        assertThrows(Exception.class, () ->
            KeyStorageUtil.loadPublicKey(nonExistentPath, "RSA")
        );
    }

    @Test
    void importPublicKeyFromInvalidBase64ThrowsException() {
        // Arrange
        String invalidBase64 = "this-is-not-valid-base64!!!";

        // Act & Assert
        assertThrows(Exception.class, () ->
            KeyStorageUtil.importPublicKeyFromBase64(invalidBase64, "RSA")
        );
    }

    // ========== Encrypted Key Storage Tests (Note: Currently not implemented) ==========

    @Test
    void savePrivateKeyEncryptedThrowsUnsupportedOperationException() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Password password = new Password("TestPassword123!");
        Path keyPath = tempDir.resolve("encrypted_private_key.pem");

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () ->
            KeyStorageUtil.savePrivateKeyEncrypted(keyPair.getPrivate(), password, keyPath)
        );
    }

    @Test
    void loadPrivateKeyEncryptedThrowsUnsupportedOperationException() throws Exception {
        // Arrange
        Password password = new Password("TestPassword123!");
        Path keyPath = tempDir.resolve("encrypted_private_key.pem");
        Files.writeString(keyPath, "dummy content");

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () ->
            KeyStorageUtil.loadPrivateKeyEncrypted(keyPath, password, "RSA")
        );
    }

    @Test
    void saveKeyPairThrowsUnsupportedOperationException() throws Exception {
        // Arrange
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(RsaKeySize.BIT_2048);
        Password password = new Password("TestPassword123!");
        Path privateKeyPath = tempDir.resolve("private_key.pem");
        Path publicKeyPath = tempDir.resolve("public_key.pem");

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () ->
            KeyStorageUtil.saveKeyPair(keyPair, password, privateKeyPath, publicKeyPath)
        );
    }

    @Test
    void loadKeyPairThrowsUnsupportedOperationException() throws Exception {
        // Arrange
        Password password = new Password("TestPassword123!");
        Path privateKeyPath = tempDir.resolve("private_key.pem");
        Path publicKeyPath = tempDir.resolve("public_key.pem");
        Files.writeString(privateKeyPath, "dummy content");
        Files.writeString(publicKeyPath, "dummy content");

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () ->
            KeyStorageUtil.loadKeyPair(privateKeyPath, publicKeyPath, password, "RSA")
        );
    }
}
