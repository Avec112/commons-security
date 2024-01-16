package io.github.avec112.security.crypto.error;

public class BadCipherConfigurationException extends Exception {
    public BadCipherConfigurationException(String message, Throwable e) {
        super(message, e);
    }

    public BadCipherConfigurationException(Throwable cause) {
        super(cause);
    }
}
