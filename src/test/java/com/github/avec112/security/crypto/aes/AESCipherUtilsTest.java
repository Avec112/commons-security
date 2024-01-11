package com.github.avec112.security.crypto.aes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class AESCipherUtilsTest {

    @Test
    void randomNonceLength() {
        int nonceLength = 10;
        byte [] nonce = AesCipherUtils.getRandomNonce(nonceLength);
        assertEquals(nonceLength, nonce.length);
    }

    /*
        1 byte Secure Random Nonce has 129 possible results
        With 10000 tries we should hit every 129 by a good margin
     */
    @ParameterizedTest
    @ValueSource(ints = 10000) // should max out 129 different bytes by far
    void testForRandomness(int tries) {
        Set<String> randomSet = new HashSet<>();
        for(int i=0;i < tries;i++) {
            byte[] randomNonce = AesCipherUtils.getRandomNonce(1);
            randomSet.add(new String(randomNonce));
        }
        assertEquals(129, randomSet.size());
    }

    /*
        Check key being created and that encoded key length matches given bit length
        bits/8 = encoded length
     */
    @ParameterizedTest
    @ValueSource(ints = {
            128,192,256
    })
    void getAESKey(int bits) throws NoSuchAlgorithmException {
        assertEquals(bits/8, AesCipherUtils.getAESKey(bits).getEncoded().length);
    }

    @ParameterizedTest
    @CsvSource({
            "AES-128,128",
            "AES-192,192",
            "AES-256,256"
    })
    void testGetAESKeyFromPasswordSameSalt(String password, int keyLengthInBits)  throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte [] salt = AesCipherUtils.getRandomNonce(16);
        SecretKey keyOne = getAESKeyFromPassword(password, salt, keyLengthInBits);
        SecretKey keyTwo = getAESKeyFromPassword(password, salt, keyLengthInBits);
        String keyOneBase64 = Base64.getEncoder().encodeToString(keyOne.getEncoded());
        String keyTwoBase64 = Base64.getEncoder().encodeToString(keyTwo.getEncoded());
        assertEquals(keyOneBase64, keyTwoBase64);

    }

    @ParameterizedTest
    @CsvSource({
            "AES-128,128",
            "AES-192,192",
            "AES-256,256"
    })
    void testGetAESKeyFromPasswordDifferentSalt(String password, int keyLengthInBits)  throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte [] salt1 = AesCipherUtils.getRandomNonce(16);
        byte [] salt2 = AesCipherUtils.getRandomNonce(16);
        SecretKey keyOne = getAESKeyFromPassword(password, salt1, keyLengthInBits);
        SecretKey keyTwo = getAESKeyFromPassword(password, salt2, keyLengthInBits);
        String keyOneBase64 = Base64.getEncoder().encodeToString(keyOne.getEncoded());
        String keyTwoBase64 = Base64.getEncoder().encodeToString(keyTwo.getEncoded());
        assertNotEquals(keyOneBase64, keyTwoBase64);

    }

    private SecretKey getAESKeyFromPassword(String password, byte[] salt, int keyLengthInBits) throws InvalidKeySpecException, NoSuchAlgorithmException {
        char[] passwordAsChars = password.toCharArray();
        EncryptionStrength aesKeyLength = EncryptionStrength.getAESKeyLength(keyLengthInBits);
        return AesCipherUtils.getAESKeyFromPassword(passwordAsChars, salt, aesKeyLength);
    }

}