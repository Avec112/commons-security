package io.github.avec112.security.crypto.password;

public enum PasswordEncoderType {
    // tag::algorithms[]
    ARGON2("argon2"), // default
    BCRYPT("bcrypt"),
    SCRYPT("scrypt"),
    PBKDF2("pbkdf2");
    // end::algorithms[]

    private final String id;

    PasswordEncoderType(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }
}
