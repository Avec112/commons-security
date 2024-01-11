package com.github.avec112.security.crypto.error;

public class MissingPlainTextException extends IllegalArgumentException {
    public MissingPlainTextException() {
        this("plainText cannot be null or blank");
    }

    public MissingPlainTextException(String message) {
        super(message);
    }
}
