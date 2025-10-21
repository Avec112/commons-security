package com.github.avec112.security.crypto.error;

public class BlankPlainTextException extends IllegalArgumentException {
    public BlankPlainTextException() {
        this("plainText cannot be null or blank");
    }

    public BlankPlainTextException(String message) {
        super(message);
    }
}
