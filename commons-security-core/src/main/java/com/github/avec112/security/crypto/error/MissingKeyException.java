package com.github.avec112.security.crypto.error;

public class MissingKeyException extends NullPointerException {

    public MissingKeyException() {
        this("key cannot be null");
    }

    public MissingKeyException(String s) {
        super(s);
    }
}
