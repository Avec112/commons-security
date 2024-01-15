package io.github.avec112.security.crypto.hybrid;

import lombok.Value;

@Value
public class PlainTextContainer {
    String privateKey;
    String encryptedKey;
    String plainText;
}
