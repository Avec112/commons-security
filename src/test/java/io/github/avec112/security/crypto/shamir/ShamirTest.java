package io.github.avec112.security.crypto.shamir;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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

    @Test
    void testAll3of5CombinationsReconstruct() {
        // Verify every combination of 3 shares (out of 5) reconstructs the original secret.
        List<int[]> triples = combinations(5, 3);
        assertEquals(10, triples.size(), "Sanity check: C(5,3) must be 10");

        for (int[] idx : triples) {
            Secret reconstructed = Shamir.getSecret(
                    shares.get(idx[0]),
                    shares.get(idx[1]),
                    shares.get(idx[2])
            );
            assertEquals(expectedSecret, reconstructed,
                    "Failed for indices: [" + idx[0] + "," + idx[1] + "," + idx[2] + "]");
        }
    }

    @Test
    void testAll2of5CombinationsDoNotReconstruct() {
        // Optional: depending on implementation, this may produce garbage or throw.
        // If your getSecret throws for < threshold, replace with assertThrows accordingly.
        List<int[]> pairs = combinations(5, 2);
        assertEquals(10, pairs.size(), "Sanity check: C(5,2) must be 10");

        for (int[] idx : pairs) {
            Secret reconstructed = Shamir.getSecret(
                    shares.get(idx[0]),
                    shares.get(idx[1])
            );
            assertNotEquals(expectedSecret, reconstructed,
                    "Unexpected success for indices: [" + idx[0] + "," + idx[1] + "]");
        }
    }

    @Test
    void testFourAndFiveOfFiveAlsoReconstruct() {
        assertEquals(expectedSecret, Shamir.getSecret(shares.get(0), shares.get(1), shares.get(2), shares.get(3)));
        assertEquals(expectedSecret, Shamir.getSecret(shares.get(0), shares.get(1), shares.get(2), shares.get(3), shares.get(4)));
    }


    // --- Helpers ---

    private static List<int[]> combinations(int n, int k) {
        // Generates all index combinations of size k from [0..n-1].
        List<int[]> result = new ArrayList<>();
        int[] combo = new int[k];
        for (int i = 0; i < k; i++) combo[i] = i;
        while (true) {
            result.add(combo.clone());
            int i = k - 1;
            while (i >= 0 && combo[i] == n - k + i) i--;
            if (i < 0) break;
            combo[i]++;
            for (int j = i + 1; j < k; j++) combo[j] = combo[j - 1] + 1;
        }
        return result;
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