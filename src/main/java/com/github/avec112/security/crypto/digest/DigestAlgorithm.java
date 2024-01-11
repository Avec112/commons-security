package com.github.avec112.security.crypto.digest;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum DigestAlgorithm {
    // tag::hashing-algorithms[]
    SHA_256 ("SHA-256"), // default
    SHA_384 ("SHA-384"),
    SHA_512 ("SHA-512"),
    SHA_512_224 ("SHA-512/224"),
    SHA_512_256 ("SHA-512/256"),
    SHA3_224 ("SHA3-224"),
    SHA3_256 ("SHA3-256"),
    SHA3_384 ("SHA3-384"),
    SHA3_512 ("SHA3-512");
    // end::hashing-algorithms[]

    private final String algorithm;

}
