package io.github.avec112.security.crypto.shamir;

import com.codahale.shamir.Scheme;
import io.github.avec112.security.encoding.EncodingUtils;
import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides static utility methods for splitting and reconstructing secrets using
 * <a href="https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing">Shamir's Secret Sharing</a> scheme.
 * <p>
 * This class acts as a simple façade around the {@link com.codahale.shamir.Scheme} implementation,
 * offering a developer-friendly API with Base64-encoded {@link Share} and {@link Shares} wrappers.
 * </p>
 * <p>
 * The generated shares can be distributed among participants, such that any subset of
 * {@code k} shares can reconstruct the original secret, while fewer than {@code k}
 * reveal no information about it.
 * </p>
 * <p>
 * This implementation uses {@link SecureRandom} for entropy and UTF-8 for encoding textual secrets.
 * </p>
 */
public class Shamir {

    private static final Pattern SHARE_PATTERN = Pattern.compile("^(\\d+)\\+(.*)$");

    private Shamir() {}

    /**
     * Splits a secret into {@code n} shares, of which any {@code k} are required to reconstruct it.
     * <p>
     * Each share is encoded as Base64 and includes both its numeric index and the share data
     * in the format {@code "index+data"}. The shares can later be recombined using
     * {@link #getSecret(Share...)}.
     * </p>
     *
     * @param secret the {@link Secret} to split; must not be {@code null}
     * @param n total number of shares to generate
     * @param k threshold number of shares required to recover the secret
     * @return a {@link Shares} collection containing the generated shares
     * @throws IllegalArgumentException if {@code n < 1}, {@code k < 1}, or {@code k > n}
     */
    public static Shares getShares(Secret secret, int n, int k) {
        Map<Integer, byte[]> shareMap = getShareMap(secret.getValue(), n, k);
        Shares shares = new Shares();
        shareMap.forEach((index, bytes) -> {
            final String indexAndShare = index + "+" + EncodingUtils.base64Encode(bytes);
            final String indexAndShareEncoded = EncodingUtils.base64Encode(indexAndShare.getBytes(StandardCharsets.UTF_8));
            shares.add(new Share(indexAndShareEncoded));
        });
        return shares;
    }

    /**
     * Reconstructs the original secret from the provided shares.
     * <p>
     * This method performs Shamir's Secret Sharing recombination using the given {@link Share} objects.
     * It does not require prior knowledge of how many total shares were originally created
     * or how many were required to recover the secret. The method simply attempts to reconstruct
     * the secret from the supplied parts — if the threshold is met, the correct secret is returned;
     * otherwise, the result will be invalid (nonsensical) data.
     * </p>
     * <p>
     * All shares must follow the expected format {@code "index+data"} and be Base64-encoded
     * as produced by {@link #getShares(Secret, int, int)}.
     * If any share has an invalid format, an {@link IllegalArgumentException} will be thrown.
     * </p>
     *
     * @param shares one or more {@link Share} objects used to reconstruct the secret;
     *               must contain at least two valid shares
     * @return the reconstructed {@link Secret}
     * @throws IllegalArgumentException if {@code shares} is {@code null}, fewer than two shares are provided,
     *                                  or a share has an invalid format
     */
    public static Secret getSecret(Share...shares) {
        Validate.notNull(shares, "Shares cannot be null");
        if(shares.length < 2) {
            throw new IllegalArgumentException("Argument Share must have at least two shares");
        }

        // create map
        final Map<Integer, byte[]> providedParts = new HashMap<>(shares.length);
        // start loop
        for(Share share:shares) {
            // decode once
            final String indexAndShare = new String(EncodingUtils.base64Decode(share.getValue()), StandardCharsets.UTF_8);
            // split out index and encoded share
            Matcher m = SHARE_PATTERN.matcher(indexAndShare);
            System.out.println("Decoded: " + indexAndShare);
            if(m.matches()) {
                String index = m.group(1);
                String s = m.group(2);
                // decode a second time
                final byte[] shareDecoded = EncodingUtils.base64Decode(s);
                // add to map
                providedParts.put(Integer.parseInt(index), shareDecoded);
            } else {
                throw new IllegalArgumentException("Invalid share format. Expected 'index+data' but got: " + indexAndShare);
            }
        }
        // schema join
        int n = providedParts.keySet().stream().max(Integer::compareTo).orElse(shares.length);
        int k = shares.length;
        Scheme scheme = new Scheme(new SecureRandom(), n, k);

        final byte[] secretAsBytes = scheme.join(providedParts);

        // return recovered
        return new Secret(new String(secretAsBytes, StandardCharsets.UTF_8));
    }

    private static Map<Integer, byte[]> getShareMap(String s, int n, int k) {
        final Scheme scheme = new Scheme(new SecureRandom(), n, k);
        final byte[] secret = s.getBytes(StandardCharsets.UTF_8);
        return scheme.split(secret);
    }
}
