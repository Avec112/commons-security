package io.github.avec112.security.crypto.error;

public class BlankCipherTextException extends IllegalArgumentException {

    public BlankCipherTextException() {
        this("cipherText cannot be null or blank");
    }

    public BlankCipherTextException(String message) {
        super(message);
    }
}
