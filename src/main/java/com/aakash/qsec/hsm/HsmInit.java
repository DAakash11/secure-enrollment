package com.aakash.qsec.hsm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class HsmInit {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String configPath = "hsm/softhsm-java.cfg";
        char[] pin = "1234".toCharArray();
        String label = "qsec-ca-key";

        // Connect to the HSM as a provider + keystore
        Provider pkcs11 = Security.getProvider("SunPKCS11").configure(configPath);
        Security.addProvider(pkcs11);
        KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11);
        ks.load(null, pin);

        // 1. Generate the EC key pair INSIDE the HSM (provider = the PKCS11 provider)
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", pkcs11);
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();   // private key is born in the token

        // 2. Build a self-signed root cert for that key pair
        X500Name name = new X500Name("CN=QSEC Root CA, O=Aakash, C=IE");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(3650, ChronoUnit.DAYS)),
                name,
                kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        // Sign the cert with the private key — signing happens INSIDE the HSM
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(pkcs11)
                .build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

        // 3. Store the cert next to the key in the token, under our label
        ks.setKeyEntry(label, kp.getPrivate(), pin, new X509Certificate[]{cert});
        ks.store(null, pin);

        System.out.println("SUCCESS — key generated in HSM and self-signed cert stored.");
        System.out.println("Alias now present: " + ks.aliases().nextElement());
        System.out.println("Cert subject: " + cert.getSubjectX500Principal());
    }
}
