package com.github.avec112.security.crypto.rsa;

import com.github.avec112.security.crypto.BouncyCastleProviderInitializer;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.PlainText;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class RsaCipherTest extends BouncyCastleProviderInitializer {

    private static KeyPair keyPair1024;
    private static KeyPair keyPair2048;
    private static KeyPair keyPair3072;
    private static KeyPair keyPair4096;

    @BeforeAll
    static void setUp() throws Exception {
        keyPair1024 = loadKeyPair(KeySize.BIT_1024);
        keyPair2048 = loadKeyPair(KeySize.BIT_2048);
        keyPair3072 = loadKeyPair(KeySize.BIT_3072);
        keyPair4096 = loadKeyPair(KeySize.BIT_4096);
    }


    /*
      Testing encrypt and decrypt with system generated keypair
     */
    @ParameterizedTest
    @EnumSource(KeySize.class)
    void encryptAndDecryptWithApplicationGeneratedKeyPair(KeySize keySize) throws Exception {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyGenerator.initialize(new RSAKeyGenParameterSpec(keySize.getKeySize(), RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = keyGenerator.generateKeyPair();

        final RsaCipher rsaCipher = new RsaCipher();
        final PlainText expectedPlainText = new PlainText("Secret text");

        // encrypt
        final CipherText cipherText = rsaCipher.encrypt(expectedPlainText, keyPair.getPublic());
        assertNotEquals(expectedPlainText.getValue(), cipherText.getValue());

        // decrypt
        final PlainText plainText = rsaCipher.decrypt(cipherText, keyPair.getPrivate());
        assertEquals(expectedPlainText, plainText);
    }
    /*
        Testing encrypt and decrypt with external KeyPair made with OpenSSL
     */

    @ParameterizedTest
    @MethodSource({"keyPair"}) // 1024, 2048, 3072, 4096
    void encryptAndDecryptWithOpenSSLKeyPair(KeyPair keyPair) throws Exception {

        RsaCipher rsaCipher = new RsaCipher();

        final PlainText expectedPlainText = new PlainText("Secret text");

        // encrypt
        final CipherText cipherText = rsaCipher.encrypt(expectedPlainText, keyPair.getPublic());
        assertNotEquals(expectedPlainText.getValue(), cipherText.getValue());
        System.out.println(cipherText);
        // decrypt
        final PlainText plainText = rsaCipher.decrypt(cipherText, keyPair.getPrivate());
        assertEquals(expectedPlainText, plainText);
    }
    /*
        Testing decrypt with private key (OpenSSL) and cipherText
     */

    @ParameterizedTest
    @MethodSource({"privateKeyAndCipherText"}) // 1024, 2048, 3072, 4096
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
                keyPair3072,
                keyPair4096
        );
    }


    private static Stream<Arguments> privateKeyAndCipherText() {
        return Stream.of(
                Arguments.of(keyPair1024.getPrivate(), "Q0wHZ5iG1WK/UWVb8Zyj/tYzHpu+qSOOm1WJHMrGY/QBL6HqwkDMPhR+TaxjAbiKYmOxxTalL2KSnGxo5pDOrmLzj/yLSaFQWoND5EGf08Gg6/BVf6O7QmDJNtHRSbUcBGEKwoR7SFVuOw0FWtzIOsHntOJD4t97ks8uTko89mg="),
                Arguments.of(keyPair2048.getPrivate(), "zMidQ/hwCco1/7nfVVIloDUZbk3h8xuWoKB6CATpt/mkPx2yzWN53W9fMNfXbKp1t8VXby3ZssPsLTuM48mztikBgNVQYc4YtLkSEUOPduZpBFR8O7djCDg/awNpMElLU4S0qvCp0zxIL2mFEz4y04gklJQ9kOPq3Vc8+EsKlqqtZ7Ks0kqQNJoH/CPcWFRe5E/lBttVLB6rEJOk6k3QbiYASpM2uTz5OZTfKhtvHm2J1u373exN4pIVyXA9zbp7IRObgEKilje3Bqo9asAzxX4zmoGpUlu73naREhTTFVMLGnvIfZNmAM698gzohZ5YBqwA+BTa2ZMIWqtJXIaAlA=="),
                Arguments.of(keyPair3072.getPrivate(), "YPH5gYcujMWeezk9NhjCd/khTINHezL1xCpCvmp+mSn2XfXXvfM8igdAAsYIbPeb8pZsK1xKjtRMADqZ6wn3OXYB4L8d2Dr4bdf/jxmuFT0ybxuY/wcUy0ikrLWUz2zhxzfq1TjXzbuTkIKVnxQ8lWDBVwTQCs6nN4TnTaGe5ssLoXuz404G8M/ImqcX/OgHhd3j0ujzWSHNVlxBG4Zykh9I0x4LPM4w3IZFlDBHXJCLYgltwmMBxkHTSMr70XVqVW0nOyM4oeP4Rh0RfbfSqE2xcvPjSHIh9OWpIiRJC+uWcKvOA9C2BJAePoZTlRkiyrlSHZa1qd6Uc/0GTy1Zkv9+iMhiYt/maQS5AGWjc9H/Y9tYy1Y5SdFYUYTcUX3n1KkJG0v5Ll+crDClEfRacrmoO0nAgqTBLaXCcAob8Bai8gIyow2cy18Gcu84cOwX2CTb5WB3fYKJ577d6j8tLu/+H0sdp1aFWGYrnNvpNFprynTaCk9xULvZdVvBwNJ4"),
                Arguments.of(keyPair4096.getPrivate(), "iRtCGCp8zh/e99EBV/KLZM19f1Hbj6auAczGCcjnmIURKzp6Nx94vwdhQaPU8wJnS4f3KMVeDm/OxHsrXwMJPrLFqt9F83ekIBaKhd4/QsXab/S9FMMLQGpVcZejndawpCqV37iypdisfr/lSotfCEBkocIqGe0R1RAKP/TV0xSpXib512BkqvsBklyJgmevAnaYtR9JhQWNgr3a7FjfbQW3BBgegbkLGFZq09KhuAFqM31peXWEEQDfYPRJ5DRVraYg/49UYgbFRqC6vHfoxwk6VLvzy0vCiATcxsarZQf2uWI9ubOlDEJ5EZ0Sig/CWxGRszek91KopWhz9LBzvdDJdUwnlpt5PepMf53Lj/pWSFhtMogAvo5rOxVtQnkQV1YhnnlBxX2fyj9dwXf3eLgfR6zEza9Q5Nngz6PcfMYxBdzaT43ww1DMYLKT9ZsvEpc/NQsrjhsBuo4kmPP+YbljGrG+0rBV4bWgTKRYFcU4O9dN+615IpX/5m896088MdYyK/5Nvb2hoNDvHJd50fam1gTImNAS+FGgsiXzhx39IH20emKFB72v6m3OqffUXxTqAzotbfkrU2QhSJF3KF/ui43WlRS89fNMlZGZB8n9WZ5Dhz/L9QKG1gnErSfI/6Ssa4e6oG64T6v6nl+ZCW1c67+FJb1OCx8KtXIbo1k="));
    }

    public static KeyPair loadKeyPair(KeySize keySize) throws Exception {

        byte[] privateKeyContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private-" + keySize.getKeySize() +".der").toURI()));
        byte[] publicKeyContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public-" + keySize.getKeySize() +".der").toURI()));

        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKeyContent);
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKeyContent);
        PublicKey pubKey = kf.generatePublic(keySpecX509);

        return new KeyPair(pubKey, privKey);
    }

}