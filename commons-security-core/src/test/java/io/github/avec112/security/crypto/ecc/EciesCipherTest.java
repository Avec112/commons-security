package io.github.avec112.security.crypto.ecc;

import io.github.avec112.security.crypto.KeyGeneratorUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ECIES encryption and decryption.
 */
class EciesCipherTest {

    private KeyPair keyPair256;
    private KeyPair keyPair384;
    private String testPlaintext;

    @BeforeEach
    void setUp() throws Exception {
        keyPair256 = KeyGeneratorUtils.generateSecp256r1KeyPair();
        keyPair384 = KeyGeneratorUtils.generateSecp384r1KeyPair();
        testPlaintext = "Hello, ECIES encryption!";
    }

    @Test
    void testEncryptAndDecryptWithSecp256r1() throws Exception {
        // Encrypt
        byte[] ciphertext = EciesCipher.encrypt(testPlaintext, keyPair256.getPublic());

        // Verify ciphertext is not null and not empty
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);

        // Decrypt
        String decrypted = EciesCipher.decrypt(ciphertext, keyPair256.getPrivate());

        // Verify
        assertEquals(testPlaintext, decrypted, "Decrypted text should match original plaintext");
    }

    @Test
    void testEncryptAndDecryptWithSecp384r1() throws Exception {
        byte[] ciphertext = EciesCipher.encrypt(testPlaintext, keyPair384.getPublic());

        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);

        String decrypted = EciesCipher.decrypt(ciphertext, keyPair384.getPrivate());
        assertEquals(testPlaintext, decrypted);
    }

    @Test
    void testEncryptAndDecryptBytes() throws Exception {
        byte[] plaintext = testPlaintext.getBytes();

        // Encrypt
        byte[] ciphertext = EciesCipher.encrypt(plaintext, keyPair256.getPublic());

        // Decrypt
        byte[] decrypted = EciesCipher.decryptToBytes(ciphertext, keyPair256.getPrivate());

        // Verify
        assertArrayEquals(plaintext, decrypted, "Decrypted bytes should match original plaintext bytes");
    }

    @Test
    void testEncryptProducesDifferentCiphertext() throws Exception {
        // ECIES includes random ephemeral keys, so each encryption should produce different ciphertext
        byte[] ciphertext1 = EciesCipher.encrypt(testPlaintext, keyPair256.getPublic());
        byte[] ciphertext2 = EciesCipher.encrypt(testPlaintext, keyPair256.getPublic());

        // Ciphertexts should be different
        assertFalse(Arrays.equals(ciphertext1, ciphertext2), "ECIES should produce different ciphertexts");

        // But both should decrypt to same plaintext
        String decrypted1 = EciesCipher.decrypt(ciphertext1, keyPair256.getPrivate());
        String decrypted2 = EciesCipher.decrypt(ciphertext2, keyPair256.getPrivate());

        assertEquals(testPlaintext, decrypted1);
        assertEquals(testPlaintext, decrypted2);
    }

    @Test
    void testDecryptWithWrongKey() throws Exception {
        byte[] ciphertext = EciesCipher.encrypt(testPlaintext, keyPair256.getPublic());

        // Try to decrypt with a different key pair
        KeyPair wrongKeyPair = KeyGeneratorUtils.generateSecp256r1KeyPair();

        assertThrows(Exception.class, () -> {
            EciesCipher.decrypt(ciphertext, wrongKeyPair.getPrivate());
        }, "Decryption with wrong key should fail");
    }

    @Test
    void testEncryptEmptyString() throws Exception {
        String emptyString = "";
        byte[] ciphertext = EciesCipher.encrypt(emptyString, keyPair256.getPublic());

        assertNotNull(ciphertext);

        String decrypted = EciesCipher.decrypt(ciphertext, keyPair256.getPrivate());
        assertEquals(emptyString, decrypted);
    }

    @Test
    void testEncryptLargeData() throws Exception {
        // Create a large string (10KB)
        StringBuilder largeData = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            largeData.append("X");
        }
        String largePlaintext = largeData.toString();

        byte[] ciphertext = EciesCipher.encrypt(largePlaintext, keyPair256.getPublic());

        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);

        String decrypted = EciesCipher.decrypt(ciphertext, keyPair256.getPrivate());
        assertEquals(largePlaintext, decrypted);
    }

    @Test
    void testEncryptWithNullPlaintext() {
        assertThrows(NullPointerException.class, () -> {
            EciesCipher.encrypt((String) null, keyPair256.getPublic());
        });
    }

    @Test
    void testEncryptWithNullPublicKey() {
        assertThrows(NullPointerException.class, () -> {
            EciesCipher.encrypt(testPlaintext, null);
        });
    }

    @Test
    void testDecryptWithNullCiphertext() {
        assertThrows(NullPointerException.class, () -> {
            EciesCipher.decrypt(null, keyPair256.getPrivate());
        });
    }

    @Test
    void testDecryptWithNullPrivateKey() throws Exception {
        byte[] ciphertext = EciesCipher.encrypt(testPlaintext, keyPair256.getPublic());

        assertThrows(NullPointerException.class, () -> {
            EciesCipher.decrypt(ciphertext, null);
        });
    }
}
