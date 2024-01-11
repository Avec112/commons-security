package io.avec.security.crypto.error;

public class MissingCipherTextException extends IllegalArgumentException {

    public MissingCipherTextException() {
        this("cipherText cannot be null or blank");
    }

    public MissingCipherTextException(String message) {
        super(message);
    }
}
