package com.aakash.qsec.ca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.aakash.qsec.hsm.HsmKeyProvider;

public class CertificateAuthority {
 
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
 
    private final PrivateKey rootPrivateKey;
    private final X509Certificate rootCertificate;
    private final Provider hsmProvider;
 
    public CertificateAuthority(HsmKeyProvider hsm, String keyLabel) throws Exception {
        this.rootPrivateKey = hsm.getPrivateKey(keyLabel);
        this.rootCertificate = hsm.getCertificate(keyLabel);
        this.hsmProvider = hsm.getProvider();
    }
 
    public X509Certificate getRootCertificate() {
        return rootCertificate;
    }
 
    // Issue a device certificate from a CSR, signing through the HSM
    public X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws Exception {
        // Verify the CSR was signed by the private key matching its own public key
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(csr.getSubjectPublicKeyInfo());
        if (!csr.isSignatureValid(verifier)) {
            throw new SecurityException("CSR signature invalid - Rejected");
        }
 
        // Build the leaf certificate: issued BY the root, subject/public key FROM the CSR
        X500Name issuer = X500Name.getInstance(rootCertificate.getSubjectX500Principal().getEncoded());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(90, ChronoUnit.DAYS));
 
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo()
        );
        // Leaf is NOT a CA
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
 
        // Sign the leaf with the root private key INSIDE the HSM
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(hsmProvider)
            .build(rootPrivateKey);
 
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }
}
