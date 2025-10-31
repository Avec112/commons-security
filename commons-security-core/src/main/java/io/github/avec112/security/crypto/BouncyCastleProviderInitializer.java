package io.github.avec112.security.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BouncyCastleProviderInitializer {


    static {
        // Remove existing BC to prevent duplicates
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

        // Insert BC as the highest priority provider (position 1)
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        // Fail fast if registration fails
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            throw new IllegalStateException("Failed to register BouncyCastle provider");
        }
    }

    protected BouncyCastleProviderInitializer() {}

}
