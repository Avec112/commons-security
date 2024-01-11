package io.avec.security.crypto.cms;

import io.avec.security.crypto.rsa.KeyUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CmsUtilsTest {

    @Test
    void createKeyTransEnvelopedObject() throws Exception {
//        KeyPair keyPair = KeyUtils.generateKeyPair2048();
//        CmsUtils.createKeyTransEnvelopedObject(keyPair.getPublic()., "test".getBytes());
    }

    @Test
    void extractKeyTransEnvelopedData() {
    }

    @Test
    void makePersonalV1Certificate() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair2048();
//        KeyPair keyPair = CmsUtils.generateKeyPair();

        final String issuer = "My app";
        final String subject = "Test Subject";
        X509Certificate certificate = CmsUtils.makePersonalV1Certificate(keyPair.getPrivate(), keyPair.getPublic(), issuer, subject);

        certificate.checkValidity();
        assertEquals("CN=" + issuer, certificate.getIssuerDN().getName());
        assertEquals("CN=" + subject, certificate.getSubjectDN().getName());
        assertEquals(1, certificate.getVersion());
//        assertEquals("SHA384WITHECDSA", certificate.getSigAlgName());
        assertEquals("SHA384WITHRSA", certificate.getSigAlgName());

    }
}