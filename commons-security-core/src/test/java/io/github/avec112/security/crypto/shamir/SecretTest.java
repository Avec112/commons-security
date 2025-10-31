package io.github.avec112.security.crypto.shamir;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class SecretTest {

    @Test
    public void simpleEqualsContract() {
        EqualsVerifier.forClass(Secret.class).verify();
    }
}