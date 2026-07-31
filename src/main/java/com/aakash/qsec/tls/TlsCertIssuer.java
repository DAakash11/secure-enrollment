package com.aakash.qsec.tls;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.aakash.qsec.ca.CertificateAuthority;
import com.aakash.qsec.hsm.HsmKeyProvider;

public class TlsCertIssuer {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Connect to the HSM and build the CA (same as your tests do)
        HsmKeyProvider hsm = new HsmKeyProvider("hsm/softhsm-java.cfg", "1234".toCharArray());
        CertificateAuthority ca = new CertificateAuthority(hsm, "qsec-ca-key");
        X509Certificate caRoot = ca.getRootCertificate();

        // Issue a SERVER cert (CN=localhost — must match the hostname clients connect to)
        issueInto(ca, caRoot, "localhost", "tls/server.p12", "serverpass");

        // Issue a CLIENT cert (CN=device-001 — the device's identity)
        issueInto(ca, caRoot, "device-001", "tls/client.p12", "clientpass");

        System.out.println("SUCCESS: server.p12 and client.p12 created in tls/");
    }

    private static void issueInto(CertificateAuthority ca, X509Certificate caRoot,
                                  String cn, String p12Path, String password) throws Exception {
        // 1. Generate a key pair for this identity
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        KeyPair keyPair = gen.generateKeyPair();

        // 2. Build a CSR for it
        X500Name subject = new X500Name("CN=" + cn + ", O=Aakash, C=IE");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        PKCS10CertificationRequest csr =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic())
                        .build(signer);

        // 3. Have the CA issue a signed cert (signing happens in the HSM)
        X509Certificate cert = ca.issueCertificate(csr);

        // 4. Bundle key + cert (+ CA root) into a PKCS#12 keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(cn, keyPair.getPrivate(), password.toCharArray(),
                new X509Certificate[]{cert, caRoot});   // full chain: leaf + root
        try (FileOutputStream fos = new FileOutputStream(p12Path)) {
            ks.store(fos, password.toCharArray());
        }
        System.out.println("Issued " + cn + " -> " + p12Path);
    }
}
