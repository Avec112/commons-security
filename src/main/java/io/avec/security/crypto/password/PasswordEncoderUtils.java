package io.avec.security.crypto.password;

import org.apache.commons.lang3.Validate;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

public class PasswordEncoderUtils {
    private final static Map<String, PasswordEncoder> encoders = new HashMap<>();

    static {
        encoders.put(PasswordEncoderType.ARGON2.name(), new Argon2PasswordEncoder());
        encoders.put(PasswordEncoderType.BCRYPT.name(), new BCryptPasswordEncoder());
        encoders.put(PasswordEncoderType.SCRYPT.name(), new SCryptPasswordEncoder());
        encoders.put(PasswordEncoderType.PBKDF2.name(), new Pbkdf2PasswordEncoder());
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
        Validate.notNull(encoderType);

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
        Validate.notNull(encoderType);

        PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(encoderType.name(), encoders);
        return passwordEncoder.matches(password, encodedPassword);
    }


}
