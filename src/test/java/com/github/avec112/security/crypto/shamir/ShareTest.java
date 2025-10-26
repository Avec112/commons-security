package com.github.avec112.security.crypto.shamir;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class ShareTest {

    @Test
    public void simpleEqualsContract() {
        EqualsVerifier.forClass(Share.class).verify();
    }
}