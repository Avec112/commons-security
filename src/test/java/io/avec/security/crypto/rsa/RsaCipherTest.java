package io.avec.security.crypto.rsa;

import io.avec.security.crypto.domain.CipherText;
import io.avec.security.crypto.domain.PlainText;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class RsaCipherTest {

    private static KeyPair keyPair1024;
    private static KeyPair keyPair2048;
    private static KeyPair keyPair4096;
    @BeforeAll
    static void setUp() throws Exception {
        keyPair1024 = loadKeyPair(KeySize.BIT_1024);
        keyPair2048 = loadKeyPair(KeySize.BIT_2048);
        keyPair4096 = loadKeyPair(KeySize.BIT_4096);
    }

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void generateKeyPair(KeySize keySize) throws NoSuchAlgorithmException {
        RsaCipher rsaCipher = new RsaCipher();
        KeyPair keyPair = rsaCipher.generateKeyPair(keySize);
        validateRsaKeyPair(keyPair, keySize);
    }

    /*
      Testing encrypt and decrypt with system generated keypair
     */

    @ParameterizedTest
    @EnumSource(KeySize.class)
    void encryptAndDecryptWithApplicationGeneratedKeyPair(KeySize algorithm) throws Exception {

        RsaCipher rsaCipher = new RsaCipher();
        KeyPair keyPair = rsaCipher.generateKeyPair(algorithm);

        final PlainText expectedPlainText = new PlainText("Secret text");

        // encrypt
        final CipherText cipherText = rsaCipher.encrypt(expectedPlainText, keyPair.getPublic());
        assertNotEquals(expectedPlainText.getValue(), cipherText);

        // decrypt
        final PlainText plainText = rsaCipher.decrypt(cipherText, keyPair.getPrivate());
        assertEquals(expectedPlainText, plainText);
    }
    /*
        Testing encrypt and decrypt with external KeyPair made with OpenSSL
     */

    @ParameterizedTest
    @MethodSource({"keyPair"}) // 1024, 2048, 4096
    void encryptAndDecryptWithOpenSSLKeyPair(KeyPair keyPair) throws Exception {

        RsaCipher rsaCipher = new RsaCipher();

        final PlainText expectedPlainText = new PlainText("Secret text");

        // encrypt
        final CipherText cipherText = rsaCipher.encrypt(expectedPlainText, keyPair.getPublic());
        assertNotEquals(expectedPlainText.getValue(), cipherText.getValue());

        // decrypt
        final PlainText plainText = rsaCipher.decrypt(cipherText, keyPair.getPrivate());
        assertEquals(expectedPlainText, plainText);
    }
    /*
        Testing decrypt with private key (OpenSSL) and cipherText
     */

    @ParameterizedTest
    @MethodSource({"privateKeyAndCipherText"}) // 1024, 2048, 4096
    void encryptAndDecryptWithOpenSSLKeyPairAndCipherText(PrivateKey privateKey, String cipherText) throws Exception {

        RsaCipher rsaCipher = new RsaCipher();

        final PlainText expectedPlainText = new PlainText("Secret text");

        // decrypt
        final PlainText plainText = rsaCipher.decrypt(new CipherText(cipherText), privateKey);
        assertEquals(expectedPlainText, plainText);
    }

    private static Stream<KeyPair> keyPair() {
        return Stream.of(
                keyPair1024,
                keyPair2048,
                keyPair4096
        );
    }


    private static Stream<Arguments> privateKeyAndCipherText() {
        return Stream.of(
                Arguments.of(keyPair1024.getPrivate(), "UnmX5wjfoEGymEIVhbBPhWAIzDx7Ma0GdAbCAHQMlbeLoccwnwAS4XQVrwtDNWQyrn0XbBghfURyRW9TBi4YNDRPPF6zPNNjsObtCVPeLCBEPETWLArHNJsaWSNv+r8xnGVOtSHr6wrpuNZkxf2lWIj8wsYj85Awn5IRBe0Zk9A="),
                Arguments.of(keyPair2048.getPrivate(), "kNBGEeBHeSlj07OXA1FLGrd59Qy+YZ8GAhS7fp1KYP0r9ti4jZAsbk6lVR5iEHRvClSR+z43diw+/waCDEVni/vQhNmI0JZtCY1bEx+cRYBulDsp0EV5slWoIogUge33TNRlkqbYHiCCShCmgVRlvMms3zebDF2z+EaBP5MXcllULSfabsE2XSiCle3Wrs7QZStBTzRCiu60rnERJLptan3Jzk9Xfwh5CmVCCFyUgydMH46rWM4XCkmsjP0/VcHWQaM3b9QE5N6KRaAybrjbAKx979K7Mmt3WIvERtDB+CkWpawREaguTwuSOJC6lIiDeOEwf6kfEQZsPjTAgBMw6Q=="),
                Arguments.of(keyPair4096.getPrivate(), "NDix82PTrElkMD2gisTDgINODbPGsVG/Ju0YcIIIjj8fUDhk1je648x9cPEolNEuOpWs2cx4ChBv+1fsWX5izvGIzT5lJa+oGltBuGH/wE/RwKE+BbtwvjJNNW9IyoGacH0Vm63IEaEkaCq7FYBjze6embfGey2gn0WR3Pk6/6YhqBDLWsF0wZg9zl8x//UNoVWgUkktObi+xMmKjhfI2NZWBPyvwfuKqLwKurnDHTLIBYPXuG7LR6AKEe+axWWVp7KsIxmD4+AN0J/XCwQXDOQyX3+b36rpH/oA4+AdYjhxtMTIC6HhjOpiS7ZFBYCIHJOLXxcjSeAq7cI9DRReqYlhbRAoSkju2BY/fUCPpxENew8TYz2zZuGx9i4NzSCovuW/GncmmTVq+ZGZLivP9EwcWm6x2y7t9M8cOI1uw3kXwQn5nhrTmVb88u5X0lEXyiwUtHyPemN1gXV2ZPDHwdERFmAXzZNr6NF+WG2W/zJTqQHFzOf8GIzECr7hDU2q/1VZDhWJD/fc0EXcI1qPjl26Ya9zyECvRhIvlIHGX4l9wRMbmOlMV/fdnX6jpdVtwlUs1/bEqxQPzRMOXO2EU1F558qaXqc7fk5Srv/ZIxo8Epekry9/SL1aV80c1Cpv3W3SlqFz4T/556nAPWXoD2xgZKiVc4hS/4WiBfc3GYQ="));
    }

    private static KeyPair loadKeyPair(KeySize keySize) throws Exception {

        byte[] privateKeyContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private-" + keySize.getKeySize() +".der").toURI()));
        byte[] publicKeyContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public-" + keySize.getKeySize() +".der").toURI()));

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKeyContent);
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKeyContent);
        PublicKey pubKey = kf.generatePublic(keySpecX509);

        return new KeyPair(pubKey, privKey);
    }


    private void validateRsaKeyPair(KeyPair keyPair, KeySize keySize) {
        assertInstanceOf(RSAPublicKey.class, keyPair.getPublic());
        assertInstanceOf(RSAPrivateKey.class, keyPair.getPrivate());

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals("RSA", rsaPublicKey.getAlgorithm());
        assertEquals("X.509", rsaPublicKey.getFormat());
        assertEquals(keySize.getKeySize(), rsaPublicKey.getModulus().bitLength());

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        assertEquals("RSA", rsaPrivateKey.getAlgorithm());
        assertEquals("PKCS#8", rsaPrivateKey.getFormat());
        assertEquals(keySize.getKeySize(), rsaPrivateKey.getModulus().bitLength());
    }
}