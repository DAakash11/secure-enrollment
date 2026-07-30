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

import com.aakash.qsec.hsm.HsmKeyProvider;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

class CertificateAuthorityTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String CONFIG = "hsm/softhsm-java.cfg";
    private static final char[] PIN = "1234".toCharArray();
    private static final String KEY_LABEL = "qsec-ca-key";

    // Helper: a device generates its own key pair (in memory, with BouncyCastle)
    private KeyPair deviceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        return gen.generateKeyPair();
    }

    // Helper: build a CSR the way a real device would
    private PKCS10CertificationRequest makeDeviceCsr(KeyPair deviceKeys, String deviceName) throws Exception {
        X500Name subject = new X500Name("CN=" + deviceName + ", O=Aakash Devices, C=IE");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(deviceKeys.getPrivate());
        return new JcaPKCS10CertificationRequestBuilder(subject, deviceKeys.getPublic())
                .build(signer);
    }

    @Test
    void hsmBackedCa_issuesCertificate_thatChainsToRoot() throws Exception {
        // Construct the CA from the HSM (integration: touches the real token)
        HsmKeyProvider hsm = new HsmKeyProvider(CONFIG, PIN);
        CertificateAuthority ca = new CertificateAuthority(hsm, KEY_LABEL);
        X509Certificate root = ca.getRootCertificate();

        // Device side
        KeyPair deviceKeys = deviceKeyPair();
        PKCS10CertificationRequest csr = makeDeviceCsr(deviceKeys, "device-001");

        // CA issues the leaf, signing through the HSM
        X509Certificate leaf = ca.issueCertificate(csr);

        // 1. Leaf carries the requested identity
        assertTrue(leaf.getSubjectX500Principal().getName().contains("device-001"));

        // 2. Leaf was issued BY the root (compare encoded names, order-independent)
        assertArrayEquals(
                root.getSubjectX500Principal().getEncoded(),
                leaf.getIssuerX500Principal().getEncoded());

        // 3. Chain of trust: leaf verifies against the root's public key.
        //    The private half lives in the HSM — this proves the HSM-signed chain holds.
        assertDoesNotThrow(() -> leaf.verify(root.getPublicKey()));

        // 4. Leaf is currently valid
        assertDoesNotThrow(() -> leaf.checkValidity());
    }

    @Test
    void hsmBackedCa_rejectsTamperedCsr() throws Exception {
        HsmKeyProvider hsm = new HsmKeyProvider(CONFIG, PIN);
        CertificateAuthority ca = new CertificateAuthority(hsm, KEY_LABEL);

        KeyPair deviceKeys = deviceKeyPair();
        PKCS10CertificationRequest goodCsr = makeDeviceCsr(deviceKeys, "device-001");

        byte[] bytes = goodCsr.getEncoded();
        bytes[bytes.length - 1] ^= 0x01; // flip one bit to simulate tampering

        assertThrows(Exception.class, () -> {
            PKCS10CertificationRequest tampered = new PKCS10CertificationRequest(bytes);
            ca.issueCertificate(tampered);
        });
    }
}
