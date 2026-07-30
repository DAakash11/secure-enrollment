package com.aakash.qsec.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.security.Signature;

import org.junit.jupiter.api.Test;

class HsmKeyProviderTest {

    // Adjust this path to your project's absolute path if needed
    private static final String CONFIG = "hsm/softhsm-java.cfg";
    private static final char[] PIN = "1234".toCharArray();

    @Test
    void canReachPrivateKeyHandle_andSignWithIt() throws Exception {
        HsmKeyProvider hsm = new HsmKeyProvider(CONFIG, PIN);

        PrivateKey key = hsm.getPrivateKey("qsec-ca-key");
        assertNotNull(key, "Should get a handle to the HSM key");

        // The handle reports its algorithm, but NOT its bytes
        assertEquals("EC", key.getAlgorithm());

        // Prove we can SIGN through the HSM
        byte[] data = "sign me".getBytes();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);      // uses the HSM handle
        sig.update(data);
        byte[] signature = sig.sign();   // the HSM performs the signing

        assertTrue(signature.length > 0, "HSM should produce a signature");
    }
}
