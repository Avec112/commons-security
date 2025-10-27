package com.github.avec112.security.crypto.aes;

import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class AesDecryptorTest {


    public static final String PASSWORD = "password";
    public static final String ENCRYPTED_TEXT = "xyz";
    @Mock
    private Password password;

    @Mock
    private CipherText cipherText;

    private AesDecryptor decryptor;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(password.getValue()).thenReturn(PASSWORD);
        when(cipherText.getValue()).thenReturn(ENCRYPTED_TEXT);
        decryptor = AesDecryptor.withPasswordAndCipherText(password, cipherText);
    }

    @Test
    void withModeDefaultGCM() {
        assertThat(decryptor.getMode()).isEqualTo(EncryptionMode.GCM);
    }

    @Test
    void withModeCTR() {
        // Arrange
        EncryptionMode mode = EncryptionMode.CTR;

        // Act
        decryptor.withMode(mode);

        // assert
        assertThat(decryptor.getMode()).isEqualTo(mode);
    }

    @Test
    void withStrengthDefault() {
        assertThat(decryptor.getStrength()).isEqualTo(EncryptionStrength.BIT_256);
    }

    @Test
    void withStrength128() {
        // Arrange
        EncryptionStrength strength = EncryptionStrength.BIT_128;

        // Act
        decryptor.withStrength(strength);

        // Assert
        assertThat(decryptor.getStrength()).isEqualTo(strength);
    }

    @Test
    void getPassword() {
        assertThat(decryptor.getPassword().getValue()).isEqualTo(PASSWORD);
    }

    @Test
    void getCipherText() {
        assertThat(decryptor.getCipherText().getValue()).isEqualTo(ENCRYPTED_TEXT);
    }

}