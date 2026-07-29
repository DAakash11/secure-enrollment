package com.aakash.qsec.ca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

class CertificateAuthorityTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // A device generates its own key pair and a CSR
    private PKCS10CertificationRequest makeDeviceCsr(KeyPair deviceKeys) throws Exception {
        X500Name subject = new X500Name("CN=device-001, O=Aakash Devices, C=IE");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(deviceKeys.getPrivate());
        return new JcaPKCS10CertificationRequestBuilder(subject, deviceKeys.getPublic())
            .build(signer);
    }

    private KeyPair deviceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        return gen.generateKeyPair();
    }

    @Test
    void ca_issuesCertificate_thatChainsToRoot() throws Exception {
        CertificateAuthority ca = new CertificateAuthority();
        X509Certificate root = ca.getRootCertificate();

        // Device side: own keys, own CSR
        KeyPair deviceKeys = deviceKeyPair();
        PKCS10CertificationRequest csr = makeDeviceCsr(deviceKeys);

        // CA issues the leaf certificate
        X509Certificate leaf = ca.issueCertificate(csr);

        // 1. The leaf's subject is the device we asked for
        assertTrue(leaf.getSubjectX500Principal().getName().contains("device-001"));

        // 2. The leaf was issued BY the root
        assertArrayEquals(
            root.getSubjectX500Principal().getEncoded(),
            leaf.getIssuerX500Principal().getEncoded());

        // 3. THE KEY TEST: the leaf's signature verifies against the root's public key.
        //    This is the chain of trust holding. If tampered, this throws.
        assertDoesNotThrow(() -> leaf.verify(root.getPublicKey()));

        // 4. The leaf is valid right now (not expired / not future-dated)
        assertDoesNotThrow(() -> leaf.checkValidity());
    
    }

    @Test
    void ca_rejectsTamperedCsr() throws Exception {
        CertificateAuthority ca = new CertificateAuthority();
        KeyPair deviceKeys = deviceKeyPair();
        PKCS10CertificationRequest goodCsr = makeDeviceCsr(deviceKeys);

        // Corrupt the CSR's bytes to simulate tampering in transit
        byte[] bytes = goodCsr.getEncoded();
        bytes[bytes.length - 1] ^= 0x01; // flip one bit

        assertThrows(Exception.class, () -> {
            PKCS10CertificationRequest tampered = new PKCS10CertificationRequest(bytes);
            ca.issueCertificate(tampered);
        });
    }
}