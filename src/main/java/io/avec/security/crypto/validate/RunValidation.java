package io.avec.security.crypto.validate;

@FunctionalInterface
public interface RunValidation {
    void validate() throws Throwable;
}
