package io.avec.security.crypto.password;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordEncoderUtilsTest {

    @ParameterizedTest
    @CsvSource({
            "Password, {ARGON2}$argon2id$v=19$m=4096,t=3,p=1",
            "Password, {ARGON2}$argon2id$v=19$m=4096,t=3,p=1",
            "Password123!, {ARGON2}$argon2id$v=19$m=4096,t=3,p=1"
    })
    void encode(String password, String expectStartsWith) {
        final String encodedPassword = PasswordEncoderUtils.encode(password);
        assertTrue(encodedPassword.startsWith(expectStartsWith));
    }

    @ParameterizedTest
    @CsvSource({
            "Password, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1$iEPXeYeiXmsGyKAjnVWhYg$glRQEguo9ymG+EU2JSOz1DE40I5A94/EEDKwDQiDXnY'",
            "Password, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1$pfFmF3om+Z1BirJyLL2YVA$7Q5iYZA7GJRco1YCHBmeEIDQ2OJwoU/smDAuBKnrhYE'",
            "Password123!, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1$A4XnnF/0JEpSxG7MPKLZtg$S8q8gatvXDX7Ef/76V8VleFwMO3c7Tdo/mLOVtiecrQ'",
    })
    void matches(String password, String encodedPassword) {
        assertTrue(PasswordEncoderUtils.matches(password, encodedPassword));
    }

    @ParameterizedTest
    @CsvSource({
            "Password",
            "Password",
            "Password123!",
    })
    void encodeAndMatches(String password) {
        final String encodedPassword = PasswordEncoderUtils.encode(password);
        assertTrue(PasswordEncoderUtils.matches(password, encodedPassword));
    }

    @ParameterizedTest
    @CsvSource({
            "ARGON2, Password, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1'",
            "BCRYPT, Password, {BCRYPT}$2a$10$",
            "SCRYPT, Password, {SCRYPT}$e0801$",
            "PBKDF2, Password, {PBKDF2}"
    })
    void encodeWithPasswordEncoderType(String encoder, String password, String expectStartsWith) {
        final String encodedPassword = PasswordEncoderUtils.encode(password, PasswordEncoderType.valueOf(encoder));
        assertTrue(encodedPassword.startsWith(expectStartsWith));
    }

    @ParameterizedTest
    @CsvSource({
            "ARGON2, Password, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'",
            "BCRYPT, Password, {BCRYPT}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "SCRYPT, Password, {SCRYPT}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=",
            "PBKDF2, Password, {PBKDF2}3c85f372f3794deddfefd0d2621bcbc030eb55a908c5ecb16bdca8479da85bdccc755650e7b5b7f6"
    })
    void matchesWithPasswordEncoderType(String encoder, String password, String encodedPassword) {
        assertTrue(PasswordEncoderUtils.matches(password, encodedPassword, PasswordEncoderType.valueOf(encoder)));
    }
}