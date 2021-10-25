package io.avec.crypto.shared;

import com.codahale.shamir.Scheme;
import io.avec.crypto.domain.Password;
import io.avec.crypto.domain.PlainText;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Shamir {


    public static List<Password> getShares(PlainText plainText, int n, int k) {
        Map<Integer, byte[]> shareMap = getShareMap(plainText.getValue(), n, k);
        List<Password> shares = new ArrayList<>(n);
        shareMap.forEach((index, bytes) -> {
            final String indexAndShare = index + "+" + encode(bytes);
            final String indexAndShareEncoded = encode(indexAndShare.getBytes(StandardCharsets.UTF_8));
            shares.add(new Password(indexAndShareEncoded));
        });
        return shares;
    }

    private static Map<Integer, byte[]> getShareMap(String s, int n, int k) {
        final Scheme scheme = new Scheme(new SecureRandom(), n, k);
        final byte[] secret = s.getBytes(StandardCharsets.UTF_8);
        return scheme.split(secret);
    }


    public static PlainText getSecret(Password...shares) {
        // create map
        final Map<Integer, byte[]> providedParts = new HashMap<>(shares.length);
        // start loop
        for(Password indexAndShareEncoded:shares) {
            // decode once
            final String indexAndShare = new String(decode(indexAndShareEncoded.getValue()), StandardCharsets.UTF_8);
            // split out index and encoded share
            Pattern p = Pattern.compile("^(\\d+)\\+(.*)$");
            Matcher m = p.matcher(indexAndShare);
            if(m.matches()) {
                String index = m.group(1);
                String share = m.group(2);
                // decode second time
                final byte[] shareDecoded = decode(share);
                // add to map
                providedParts.put(Integer.parseInt(index), shareDecoded);
            } else {
                String msg = String.format("Share %s (%s) is missing index (aka. share key)", indexAndShareEncoded, indexAndShare);
                throw new IllegalStateException(msg);
            }


        }
        // schema join
        Scheme scheme = new Scheme(new SecureRandom(), 100, 100);
        final byte[] secretAsBytes = scheme.join(providedParts);

        // return recovered
        return new PlainText(new String(secretAsBytes, StandardCharsets.UTF_8));
    }

    private static String encode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static byte[] decode(String s) {
        return Base64.getDecoder().decode(s);
    }
}
