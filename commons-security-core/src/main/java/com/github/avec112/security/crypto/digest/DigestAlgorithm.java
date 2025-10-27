package com.github.avec112.security.crypto.digest;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum DigestAlgorithm {
    // tag::algorithms[]
    SHA_256("SHA-256"),
    SHA_512_256("SHA-512/256"), // default
    SHA3_256("SHA3-256"),
    SHA3_512("SHA3-512");
    // end::algorithms[]

    private final String algorithm;

}
