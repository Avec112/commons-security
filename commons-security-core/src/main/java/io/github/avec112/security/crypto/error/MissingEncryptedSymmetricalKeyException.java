package io.github.avec112.security.crypto.error;

public class MissingEncryptedSymmetricalKeyException extends IllegalArgumentException {
    public MissingEncryptedSymmetricalKeyException() {
        this("encryptedSymmetricalKeyException cannot be null or blank");
    }

    public MissingEncryptedSymmetricalKeyException(String message) {
        super(message);
    }
}
