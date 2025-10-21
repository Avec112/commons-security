package com.github.avec112.security.crypto.password;

import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.CONCURRENT)
class PasswordEncoderUtilsTest {

    @ParameterizedTest
    @CsvSource({
            "Password, '{argon2}$argon2id$v=19$m=16384,t=2,p=1'",
            "Password, '{argon2}$argon2id$v=19$m=16384,t=2,p=1'",
            "Password123!, '{argon2}$argon2id$v=19$m=16384,t=2,p=1'"
    })
    void encode(String password, String expectStartsWith) {
        final String encodedPassword = PasswordEncoderUtils.encode(password);
        assertTrue(encodedPassword.startsWith(expectStartsWith));
    }

    @ParameterizedTest
    @CsvSource({
            "Password, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$iEPXeYeiXmsGyKAjnVWhYg$glRQEguo9ymG+EU2JSOz1DE40I5A94/EEDKwDQiDXnY'",
            "Password, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$pfFmF3om+Z1BirJyLL2YVA$7Q5iYZA7GJRco1YCHBmeEIDQ2OJwoU/smDAuBKnrhYE'",
            "Password123!, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$A4XnnF/0JEpSxG7MPKLZtg$S8q8gatvXDX7Ef/76V8VleFwMO3c7Tdo/mLOVtiecrQ'",
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
//            "ARGON2, Password, '{ARGON2}$argon2id$v=19$m=4096,t=3,p=1'",
//            "BCRYPT, Password, {BCRYPT}$2a$10$",
//            "SCRYPT, Password, {SCRYPT}$e0801$",
            "PBKDF2, Password, {pbkdf2}"
    })
    void encodeWithPasswordEncoderType(String encoder, String password, String expectStartsWith) {
        final String encodedPassword = PasswordEncoderUtils.encode(password, PasswordEncoderType.valueOf(encoder));
        assertTrue(encodedPassword.startsWith(expectStartsWith));
    }

    @ParameterizedTest
    @CsvSource({
            "ARGON2, Password, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'",
            "BCRYPT, Password, {bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "SCRYPT, Password, {scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=",
            "PBKDF2, Password, {pbkdf2}3982ab2f19a3f8de63a110246301348fffc94c8fe96955771cdfd14ad41e3461946af959f92699bf31efc7cc4065592f"
    })
    void matchesWithPasswordEncoderType(String encoder, String password, String encodedPassword) {
        assertTrue(PasswordEncoderUtils.matches(password, encodedPassword, PasswordEncoderType.valueOf(encoder)));
    }

    @ParameterizedTest
    @CsvSource({
            "WrongPassword, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$iEPXeYeiXmsGyKAjnVWhYg$glRQEguo9ymG+EU2JSOz1DE40I5A94/EEDKwDQiDXnY'",
            "Password!, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$pfFmF3om+Z1BirJyLL2YVA$7Q5iYZA7GJRco1YCHBmeEIDQ2OJwoU/smDAuBKnrhYE'",
            "Password123, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$A4XnnF/0JEpSxG7MPKLZtg$S8q8gatvXDX7Ef/76V8VleFwMO3c7Tdo/mLOVtiecrQ'",
    })
    void matchesShouldReturnFalseForWrongPassword(String wrongPassword, String encodedPassword) {
        assertFalse(PasswordEncoderUtils.matches(wrongPassword, encodedPassword));
    }

    @ParameterizedTest
    @CsvSource({
            "ARGON2, WrongPassword, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'",
            "BCRYPT, WrongPassword, {bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "SCRYPT, WrongPassword, {scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=",
            "PBKDF2, WrongPassword, {pbkdf2}3982ab2f19a3f8de63a110246301348fffc94c8fe96955771cdfd14ad41e3461946af959f92699bf31efc7cc4065592f"
    })
    void matchesShouldReturnFalseForWrongPasswordAndEncoderType(String encoder, String wrongPassword, String encodedPassword) {
        assertFalse(PasswordEncoderUtils.matches(wrongPassword, encodedPassword, PasswordEncoderType.valueOf(encoder)));
    }

    @ParameterizedTest
    @CsvSource({
            "{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c",
            "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "{scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=",
            "{pbkdf2}3982ab2f19a3f8de63a110246301348fffc94c8fe96955771cdfd14ad41e3461946af959f92699bf31efc7cc4065592f"
    })
    void validateEncoderPrefixFormat(String encodedPassword) {
        assertTrue(
                encodedPassword.matches("^\\{(argon2|bcrypt|scrypt|pbkdf2)}.*$"),
                () -> "Invalid prefix format in encoded password: " + encodedPassword
        );
    }

    // Optionally test that invalid prefixes are detected
    @ParameterizedTest
    @CsvSource({
            "{UNKNOWN}abcdef",
            "ARGON2$missingBraces",
            "{bcrypt}$lowercasePrefix"
    })
    void validateInvalidPrefixFormat(String encodedPassword) {
        assertFalse(
                encodedPassword.matches("^\\{(ARGON2|BCRYPT|SCRYPT|PBKDF2)}.*$"),
                () -> "Invalid prefix should not match: " + encodedPassword
        );
    }

    @ParameterizedTest
    @CsvSource({
            "BCRYPT, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'",
            "SCRYPT, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'",
            "PBKDF2, '{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c'"
    })
    void verifyDelegatingPasswordEncoderResolvesByPrefix(String wrongEncoder, String argon2Hash) {
        assertTrue(
                PasswordEncoderUtils.matches("Password", argon2Hash, PasswordEncoderType.valueOf(wrongEncoder)),
                "DelegatingPasswordEncoder should resolve by prefix and still validate regardless of default encoder"
        );
    }


    @ParameterizedTest
    @CsvSource({
            "ARGON2, {bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "SCRYPT, {bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK",
            "PBKDF2, {bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK"
    })
    void verifyDelegatingPasswordEncoderUsesPrefix(String wrongEncoder, String bcryptHash) {
        assertTrue(
                PasswordEncoderUtils.matches("Password", bcryptHash, PasswordEncoderType.valueOf(wrongEncoder)),
                "DelegatingPasswordEncoder should still validate based on {bcrypt} prefix, regardless of default encoder"
        );
    }

    @ParameterizedTest
    @CsvSource({
            "'{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c', argon2",
            "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK, bcrypt",
            "{scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=, scrypt",
            "{pbkdf2}3982ab2f19a3f8de63a110246301348fffc94c8fe96955771cdfd14ad41e3461946af959f92699bf31efc7cc4065592f, pbkdf2"
    })
    void getPasswordEncoderType(String encodedPassword, String expected) {
        assertEquals(expected, PasswordEncoderUtils.getPasswordEncoderType(encodedPassword).id());
    }

    @ParameterizedTest
    @CsvSource({
            "'{argon2}$argon2id$v=19$m=4096,t=3,p=1$fwWOqRq6rOaSHGzCEA1p7A$lpxeUs+74bvj+kZdRO4Mna/jerRp0NueMZMZGRc+k1c', argon2",
            "{bcrypt}$2a$10$1GP39z1I.C.JHX9Qn7AepezSCYYQ53eINFFlcfnKpkHDwNemmGLyK, bcrypt",
            "{scrypt}$e0801$3WQIalromBXCD0qL+q1j1R0pWmyHMkO0NteGGDc+TEBaIG25JMUNtmLtH/aNcMO+xbD21pv1hrM1zX29MwJ2oQ==$vmfA1aDb6vFKVH7JfqYOjM9iVMa2STgqJqFgHbcyNoA=, scrypt",
            "{pbkdf2}3982ab2f19a3f8de63a110246301348fffc94c8fe96955771cdfd14ad41e3461946af959f92699bf31efc7cc4065592f, pbkdf2"
    })
    void getPasswordEncoderTypeAsString(String encodedPassword, String expected) {
        assertEquals(expected, PasswordEncoderUtils.getPasswordEncoderTypeAsString(encodedPassword));
    }

}