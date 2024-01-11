package com.github.avec112.security.crypto.shamir;

import lombok.Value;

import java.util.ArrayList;
import java.util.List;


//@NoArgsConstructor(force = true)
@Value
public class Shares {
    List<Share> shares = new ArrayList<>();

    void add(Share share) {
        shares.add(share);
    }

    public Share get(int i) {
        return shares.get(i);
    }
}
