package com.github.avec112.security.crypto.password;

import org.apache.commons.lang3.Validate;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for handling password encoding and matching using various encoding schemes.
 * Supports common encoding types such as Argon2, BCrypt, SCrypt, and PBKDF2.
 * This class provides methods for encoding plaintext passwords and verifying encoded passwords.
 *
 * The encoded password can optionally include a prefix indicating the encoding type.
 * For example, "{argon2}$argon2id$v=..." indicates the use of Argon2 encoding.
 *
 * This class relies on the DelegatingPasswordEncoder to delegate encoding and matching
 * operations to the appropriate password encoder based on the specified or implied encoding type.
 */
public class PasswordEncoderUtils {

    private static final Pattern PREFIX_PATTERN = Pattern.compile("^\\{([a-zA-Z0-9_-]+)}");
    private static final Map<String, PasswordEncoder> ENCODERS;
    private static final PasswordEncoderType DEFAULT_ENCODER = PasswordEncoderType.ARGON2;

    static {
        Map<String, PasswordEncoder> map = new HashMap<>();
        map.put(PasswordEncoderType.ARGON2.id(), Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        map.put(PasswordEncoderType.SCRYPT.id(), SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
        map.put(PasswordEncoderType.BCRYPT.id(), new BCryptPasswordEncoder());
        map.put(PasswordEncoderType.PBKDF2.id(), Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        ENCODERS = Collections.unmodifiableMap(map);
    }

    /**
     * Private constructor to prevent instantiation of the {@code PasswordEncoderUtils} utility class.
     *
     * This class is designed to provide static utility methods related to password encoding
     * and matching, and should not be instantiated.
     */
    private PasswordEncoderUtils(){}

    /**
     * Creates a delegating password encoder based on the specified password encoder type.
     *
     * @param type the password encoder type to delegate to; must not be null
     * @return a {@link PasswordEncoder} instance configured to delegate to the specified type
     */
    private static PasswordEncoder delegating(PasswordEncoderType type) {
        return new DelegatingPasswordEncoder(type.id(), ENCODERS);
    }

    /**
     * Will encode with ARGON2 encoder
     * @param password plaintext password to encode
     * @return encoded password
     */
    public static String encode(String password) {
        Validate.notBlank(password);
        return encode(password, PasswordEncoderType.ARGON2);
    }

    /**
     * Encodes the provided plaintext password using the specified password encoder type.
     *
     * @param password the plaintext password to encode; must not be blank
     * @param encoderType the type of password encoder to use for encoding; must not be null
     * @return the encoded password as a string
     */
    public static String encode(String password, PasswordEncoderType encoderType) {
        Validate.notBlank(password);
        Objects.requireNonNull(encoderType);

        PasswordEncoder passwordEncoder = delegating(encoderType);
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


        return matches(password, encodedPassword, DEFAULT_ENCODER);
    }


    /**
     * Verifies whether a plaintext password matches an encoded password using a specified password encoder type.
     *
     * @param password the plaintext password to verify; must not be blank
     * @param encodedPassword the encoded password to compare against; must not be blank
     * @param encoderType the type of password encoder to use for matching; must not be null
     * @return true if the plaintext password matches the encoded password, false otherwise
     */
    public static boolean matches(String password, String encodedPassword, PasswordEncoderType encoderType) {
        Validate.notBlank(password);
        Validate.notBlank(encodedPassword);
        Objects.requireNonNull(encoderType);

        PasswordEncoder passwordEncoder = delegating(encoderType);
        return passwordEncoder.matches(password, encodedPassword);
    }

    /**
     * Extracts the password encoder type (e.g. "argon2", "bcrypt", "scrypt", "pbkdf2")
     * from an encoded password string.
     *
     * @param encodedPassword the encoded password string, must start with {id}
     * @return the PasswordEncoderType if recognized
     * @throws IllegalArgumentException if no valid prefix is found or unsupported type
     */
    public static PasswordEncoderType getPasswordEncoderType(String encodedPassword) {
        Validate.notBlank(encodedPassword, "Encoded password cannot be null or blank");

        Matcher matcher = PREFIX_PATTERN.matcher(encodedPassword);
        if (matcher.find()) {
            String id = matcher.group(1).toLowerCase();
            for (PasswordEncoderType type : PasswordEncoderType.values()) {
                if (type.id().equalsIgnoreCase(id)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unsupported password encoder type: " + id);
        }

        throw new IllegalArgumentException("Encoded password does not contain a valid prefix: " + encodedPassword);
    }

    /**
     * Convenience method returning the encoder type as string.
     * @return the password encoder type as string
     */
    public static String getPasswordEncoderTypeAsString(String encodedPassword) {
        return getPasswordEncoderType(encodedPassword).id();
    }

    /**
     * Checks if an encoded password needs to be upgraded to a stronger algorithm.
     * Returns true if the current encoding type is different from the target type.
     *
     * @param encodedPassword the currently encoded password
     * @param targetType the desired password encoder type (typically ARGON2)
     * @return true if the password should be re-encoded with the target type
     */
    public static boolean needsUpgrade(String encodedPassword, PasswordEncoderType targetType) {
        Validate.notBlank(encodedPassword);
        Objects.requireNonNull(targetType);

        try {
            PasswordEncoderType currentType = getPasswordEncoderType(encodedPassword);
            return currentType != targetType;
        } catch (IllegalArgumentException e) {
            // If we can't determine the type, assume it needs upgrade
            return true;
        }
    }

    /**
     * Checks if an encoded password needs to be upgraded to the default algorithm (ARGON2).
     *
     * @param encodedPassword the currently encoded password
     * @return true if the password should be re-encoded with ARGON2
     */
    public static boolean needsUpgrade(String encodedPassword) {
        return needsUpgrade(encodedPassword, DEFAULT_ENCODER);
    }

    /**
     * Upgrades an encoded password from one encoder type to another.
     * This method verifies the raw password against the old encoded password,
     * and if valid, re-encodes it with the target encoder type.
     *
     * @param rawPassword the plaintext password to verify and re-encode
     * @param oldEncodedPassword the currently encoded password
     * @param targetType the desired password encoder type for the upgrade
     * @return the newly encoded password with the target encoder type
     * @throws IllegalArgumentException if the raw password does not match the old encoded password
     */
    public static String upgradePassword(String rawPassword, String oldEncodedPassword, PasswordEncoderType targetType) {
        Validate.notBlank(rawPassword);
        Validate.notBlank(oldEncodedPassword);
        Objects.requireNonNull(targetType);

        // Get the current encoder type
        PasswordEncoderType currentType = getPasswordEncoderType(oldEncodedPassword);

        // Verify the raw password matches the old encoded password
        if (!matches(rawPassword, oldEncodedPassword, currentType)) {
            throw new IllegalArgumentException("Raw password does not match the encoded password");
        }

        // Re-encode with the target encoder type
        return encode(rawPassword, targetType);
    }

    /**
     * Upgrades an encoded password to the default encoder type (ARGON2).
     * This method verifies the raw password against the old encoded password,
     * and if valid, re-encodes it with ARGON2.
     *
     * @param rawPassword the plaintext password to verify and re-encode
     * @param oldEncodedPassword the currently encoded password
     * @return the newly encoded password with ARGON2
     * @throws IllegalArgumentException if the raw password does not match the old encoded password
     */
    public static String upgradePassword(String rawPassword, String oldEncodedPassword) {
        return upgradePassword(rawPassword, oldEncodedPassword, DEFAULT_ENCODER);
    }

}
