package io.github.avec112.security.crypto.error;

public class MissingPrivateKeyException extends NullPointerException {

    public MissingPrivateKeyException() {
        this("privateKey cannot be null");
    }

    public MissingPrivateKeyException(String s) {
        super(s);
    }
}
