package io.github.avec112.security.crypto.shamir;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ShamirTest {

    private Secret expectedSecret = new Secret("My secret!");
    private Shares shares;

    @BeforeEach
    void setUp() {
        shares = Shamir.getShares(expectedSecret, 5, 3);
    }

    @Test
    void testShamir() {
        final Secret actual = Shamir.getSecret(shares.get(0), shares.get(2), shares.get(4));

        assertEquals(expectedSecret, actual);
    }


    @Test
    void testShamirToFewShares() {
        final Secret actual = Shamir.getSecret(shares.get(0), shares.get(2));

        assertNotEquals(expectedSecret.getValue(), actual.getValue());
    }


    @Test
    void testShamirWrongShareEncodedOnce() {

        byte[] wrongShare = "just wrong".getBytes(StandardCharsets.UTF_8);
        String encodeOnce = encode(wrongShare);

        assertThrows(IllegalArgumentException.class, () ->
                Shamir.getSecret(shares.get(0), shares.get(2), new Share(encodeOnce)));
    }

    @Test
    void testShamirWrongShareEncodedTwice() {

        byte[] wrongShare = "just wrong".getBytes(StandardCharsets.UTF_8);
        String encodeOnce = encode(wrongShare);
        String encodedTwice = encode(("10+" + encodeOnce).getBytes(StandardCharsets.UTF_8));

        final Secret actual = Shamir.getSecret(shares.get(0), shares.get(2), new Share(encodedTwice));

        assertNotEquals(expectedSecret, actual);
    }

    @Test
    void testShamirLargeSecret() {
        expectedSecret = new Secret(longSecret());
        shares = Shamir.getShares(expectedSecret, 4, 2);

        final Secret actual = Shamir.getSecret(shares.get(1), shares.get(3));

        assertEquals(expectedSecret, actual);
    }

    @Test
    void testInvalidThresholdGreaterThanTotal() {
        assertThrows(IllegalArgumentException.class,
                () -> Shamir.getShares(expectedSecret, 3, 5),
                "Should throw when threshold (k) is greater than total shares (n)");
    }

    @Test
    void testInvalidThresholdLessThanOne() {
        assertThrows(IllegalArgumentException.class,
                () -> Shamir.getShares(expectedSecret, 5, 0),
                "Should throw when threshold (k) is less than 1");
    }

    @Test
    void testInvalidTotalSharesLessThanOne() {
        assertThrows(IllegalArgumentException.class,
                () -> Shamir.getShares(expectedSecret, 0, 0),
                "Should throw when total shares (n) is less than 1");
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