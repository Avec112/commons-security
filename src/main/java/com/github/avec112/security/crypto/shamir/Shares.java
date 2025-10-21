package com.github.avec112.security.crypto.shamir;

import lombok.NonNull;
import lombok.Value;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;


@Value
public class Shares implements Iterable<Share> {
    List<Share> shares = new ArrayList<>();

    void add(Share share) {
        shares.add(share);
    }

    public Share get(int i) {
        return shares.get(i);
    }

    public int size() {
        return shares.size();
    }

    @NonNull
    @Override
    public Iterator<Share> iterator() {
        return shares.iterator();
    }

    public Stream<Share> stream() {
        return shares.stream();
    }
}
