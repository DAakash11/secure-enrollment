package com.aakash.qsec.ca;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CertificateAuthority {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair rootKeyPair;
    private final X509Certificate rootCertificate;

    public CertificateAuthority() throws Exception {
        this.rootKeyPair = generateEcKeyPair();
        this.rootCertificate = buildRootCertificate(rootKeyPair);
    }

    public KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        return gen.generateKeyPair();
    }

    public X509Certificate buildRootCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=QSEC ROOT CA, O=Aakash, C=IE");
        X500Name subject = issuer;

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBeofre = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(3650, ChronoUnit.DAYS));
        X509v3CertificateBuilder builder = 
            new JcaX509v3CertificateBuilder(issuer, serial, notBeofre, notAfter, subject, keyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = 
            new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }

    public X509Certificate getRootCertificate() {
        return rootCertificate;
    }

    public PrivateKey getRootPrivateKey() {
        return rootKeyPair.getPrivate();
    }

    // Issue a device certificate
    public X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws Exception {
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(csr.getSubjectPublicKeyInfo());
        if (!csr.isSignatureValid(verifier)) {
            throw new SecurityException("CSR signature invalid - Rejected");
        }

        X500Name issuer = X500Name.getInstance(rootCertificate.getSubjectX500Principal().getEncoded());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBeofre = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(90, ChronoUnit.DAYS));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            issuer, serial, notBeofre, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo()
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(rootKeyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }

}
