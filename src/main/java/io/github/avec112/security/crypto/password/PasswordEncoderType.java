package io.github.avec112.security.crypto.password;

public enum PasswordEncoderType {
    ARGON2("argon2"), // recommended
    BCRYPT("bcrypt"),
    SCRYPT("scrypt"),
    PBKDF2("pbkdf2"),;

    private final String id;

    PasswordEncoderType(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }
}
