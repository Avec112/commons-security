package io.avec.security.crypto.cms;

import io.avec.security.crypto.BouncyCastleProviderInitializer;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.spec.OAEPParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class CmsUtils extends BouncyCastleProviderInitializer {

    private CmsUtils() {}

    public static byte[] createKeyTransEnvelopedObject(X509Certificate encryptionCert, byte[] data)
            throws GeneralSecurityException, CMSException, IOException
    {
        CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        envelopedGen.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(
                        encryptionCert,
                        paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                                OAEPParameterSpec.DEFAULT)).setProvider("BC")); // or BCFIPS
        return envelopedGen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider("BC").build()).getEncoded(); // or BCFIPS
    }

    public static byte[] extractKeyTransEnvelopedData(
            PrivateKey privateKey, X509Certificate encryptionCert, byte[] encEnvelopedData)
            throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        Collection<RecipientInformation> c = recipients.getRecipients(new JceKeyTransRecipientId(encryptionCert));
        Iterator<RecipientInformation> it = c.iterator();
        if (it.hasNext())
        {
            RecipientInformation recipient = it.next();
            return recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey)
                    .setProvider("BC")); // or BCFIPS
        }
        throw new IllegalArgumentException("recipient for certificate not found");
    }

    public static X509Certificate makePersonalV1Certificate(PrivateKey caSignerKey, PublicKey caPublicKey, String issuer, String subject)
            throws GeneralSecurityException, OperatorCreationException {
        Validate.notNull(caSignerKey);
        Validate.notNull(caPublicKey);
        Validate.notBlank(issuer);
        Validate.notBlank(subject);

        System.out.println("private key: " + caSignerKey);
        System.out.println("private key format: " + caSignerKey.getFormat());
        System.out.println("private key algo: " + caSignerKey.getAlgorithm());


        X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
                new X500Name("CN=" + issuer),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - (1000L * 5)),
                new Date(System.currentTimeMillis() + (1000L * 3600 *365 * 10)), // ten years todo as param
                new X500Name("CN=" + subject),
                caPublicKey);
//        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withECDSA")
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withRSA")
                .setProvider("BC");
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(v1CertBldr.build(signerBuilder.build(caSignerKey)));
    }

    public static KeyPair generateKeyPair()
            throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");
//        keyPair.initialize(3072);
        keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPair.generateKeyPair();
    }

//    public static byte[] createEnvelope(X509Certificate encryptionCert, String data) throws CMSException {
//        Validate.notBlank(data);
//        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
//        CMSTypedData cmsTypedData = new CMSProcessableByteArray(data.getBytes());
//        OutputEncryptor outputEncryptor = new OutputEncryptor() {
//            @Override
//            public AlgorithmIdentifier getAlgorithmIdentifier() {
//                return null;
//            }
//
//            @Override
//            public OutputStream getOutputStream(OutputStream outputStream) {
//                return null;
//            }
//
//            @Override
//            public GenericKey getKey() {
//                return null;
//            }
//        };
//        CMSEnvelopedData envelopedData = generator.generate(cmsTypedData, CMSEnvelopedDataGenerator.AES256_CBC);
//    }
}
