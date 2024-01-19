package io.github.avec112.security.crypto.aes;

import io.github.avec112.security.crypto.domain.Password;
import io.github.avec112.security.crypto.domain.PlainText;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class AesEncryptorTest {

    public static final String PASSWORD = "password";
    public static final String PLAIN_TEXT = "plaintext";
    @Mock
    private Password password;

    @Mock
    private PlainText plainText;

    private AesEncryptor encryptor;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(password.getValue()).thenReturn(PASSWORD);
        when(plainText.getValue()).thenReturn(PLAIN_TEXT);
        encryptor = AesEncryptor.withPasswordAndText(password, plainText);
    }

    @Test
    void withModeDefault() {
        assertThat(encryptor.getMode()).isEqualTo(EncryptionMode.GCM);
    }

    @Test
    void withModeCTR() {
        // Arrange
        EncryptionMode mode = EncryptionMode.CTR;

        // Act
        encryptor.withMode(mode);

        // assert
        assertThat(encryptor.getMode()).isEqualTo(mode);
    }

    @Test
    void withStrengthDefault() {
        assertThat(encryptor.getStrength()).isEqualTo(EncryptionStrength.BIT_256);
    }

    @Test
    void withStrength128() {
        // Arrange
        EncryptionStrength strength = EncryptionStrength.BIT_128;

        // Act
        encryptor.withStrength(strength);

        // Assert
        assertThat(encryptor.getStrength()).isEqualTo(strength);
    }

    @Test
    void getPassword() {
        assertThat(encryptor.getPassword().getValue()).isEqualTo(PASSWORD);
    }

    @Test
    void getPlainText() {
        assertThat(encryptor.getPlainText().getValue()).isEqualTo(PLAIN_TEXT);
    }
}