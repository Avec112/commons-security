package io.github.avec112.security.crypto.shamir;

import com.codahale.shamir.Scheme;
import io.github.avec112.security.encoding.EncodingUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Shamir class provides methods for generating and recovering secret shares using Shamir's Secret Sharing.
 */
public class Shamir {

    private Shamir() {}

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

    public static Secret getSecret(Share...shares) {
        // create map
        final Map<Integer, byte[]> providedParts = new HashMap<>(shares.length);
        // start loop
        for(Share share:shares) {
            // decode once
            final String indexAndShare = new String(EncodingUtils.base64Decode(share.getValue()), StandardCharsets.UTF_8);
            // split out index and encoded share
            Pattern p = Pattern.compile("^(\\d+)\\+(.*)$");
            Matcher m = p.matcher(indexAndShare);
            if(m.matches()) {
                String index = m.group(1);
                String s = m.group(2);
                // decode second time
                final byte[] shareDecoded = EncodingUtils.base64Decode(s);
                // add to map
                providedParts.put(Integer.parseInt(index), shareDecoded);
            } else {
                String msg = String.format("Share %s (%s) is missing index (aka. share key)", share, indexAndShare);
                throw new IllegalStateException(msg);
            }
        }
        // schema join
        Scheme scheme = new Scheme(new SecureRandom(), 100, 100);
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
