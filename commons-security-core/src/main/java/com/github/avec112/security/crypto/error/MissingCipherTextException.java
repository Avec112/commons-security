package com.github.avec112.security.crypto.error;

public class MissingCipherTextException extends NullPointerException {

    public MissingCipherTextException() {
        this("cipherText cannot be null or blank");
    }

    public MissingCipherTextException(String message) {
        super(message);
    }
}
