package com.github.avec112.security.crypto.password;

import org.apache.commons.lang3.Validate;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PasswordEncoderUtils {
    private final static Map<String, PasswordEncoder> encoders = new HashMap<>();

    static {
        encoders.put(PasswordEncoderType.ARGON2.name(), Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put(PasswordEncoderType.BCRYPT.name(), new BCryptPasswordEncoder());
        encoders.put(PasswordEncoderType.SCRYPT.name(), SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put(PasswordEncoderType.PBKDF2.name(), Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
    }

    private PasswordEncoderUtils(){}

    /**
     * Will encode with ARGON2 encoder
     * @param password plaintext password to encode
     * @return encoded password
     */
    public static String encode(String password) {
        Validate.notBlank(password);
        return encode(password, PasswordEncoderType.ARGON2);
    }

    public static String encode(String password, PasswordEncoderType encoderType) {
        Validate.notBlank(password);
        Objects.requireNonNull(encoderType);

        PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(encoderType.name(), encoders);
        return passwordEncoder.encode(password);
    }

    /**
     * Match password with ARGON2 encoded password
     * @param password plaintext password to encode
     * @param encodedPassword expected to be encoded with ARGON2
     * @return true if password match
     */
    public static boolean matches(String password, String encodedPassword) {
        Validate.notBlank(password);
        Validate.notBlank(encodedPassword);

        return matches(password, encodedPassword, PasswordEncoderType.ARGON2);
    }

    public static boolean matches(String password, String encodedPassword, PasswordEncoderType encoderType) {
        Validate.notBlank(password);
        Validate.notBlank(encodedPassword);
        Objects.requireNonNull(encoderType);

        PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(encoderType.name(), encoders);
        return passwordEncoder.matches(password, encodedPassword);
    }


}
