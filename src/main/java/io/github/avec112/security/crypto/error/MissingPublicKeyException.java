package io.github.avec112.security.crypto.error;

public class MissingPublicKeyException extends NullPointerException {
    public MissingPublicKeyException() {
        this("publicKey cannot be null");
    }

    public MissingPublicKeyException(String message) {
        super(message);
    }
}
