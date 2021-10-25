package io.avec.crypto.shared;

import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ShamirTest {

    private PlainText expectedPlainText = new PlainText("My secret!");
    private List<Password> shares;

    @BeforeEach
    void setUp() {
        shares = Shamir.getShares(expectedPlainText, 5, 3);
    }

    @Test
    void testShamir() {
        final PlainText actual = Shamir.getSecret(shares.get(0), shares.get(2), shares.get(4));

        assertEquals(expectedPlainText, actual);
    }


    @Test
    void testShamirToFewShares() {
        final PlainText actual = Shamir.getSecret(shares.get(0), shares.get(2));

        assertNotEquals(expectedPlainText.getValue(), actual.getValue());
    }


    @Test
    void testShamirWrongShareEncodedOnce() {

        byte[] wrongShare = "just wrong".getBytes(StandardCharsets.UTF_8);
        String encodeOnce = encode(wrongShare);

        assertThrows(IllegalStateException.class, () ->
                Shamir.getSecret(shares.get(0), shares.get(2), new Password(encodeOnce)));
    }

    @Test
    void testShamirWrongShareEncodedTwice() {

        byte[] wrongShare = "just wrong".getBytes(StandardCharsets.UTF_8);
        String encodeOnce = encode(wrongShare);
        String encodedTwice = encode(("10+" + encodeOnce).getBytes(StandardCharsets.UTF_8));

        final PlainText actual = Shamir.getSecret(shares.get(0), shares.get(2), new Password(encodedTwice));

        assertNotEquals(expectedPlainText, actual);
    }

    @Test
    void testShamirLargeSecret() {
        expectedPlainText = new PlainText(longSecret());
        shares = Shamir.getShares(expectedPlainText, 4, 2);

        final PlainText actual = Shamir.getSecret(shares.get(1), shares.get(3));

        assertEquals(expectedPlainText, actual);
    }

    private String longSecret() {
        byte[] array = new byte[100000]; // 100 Kb
        new Random().nextBytes(array);
        return encode(array);
    }

    private String encode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

}