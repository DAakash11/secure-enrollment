package com.aakash.qsec.hsm;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class HsmKeyProvider {

    private final KeyStore keyStore;
    private final char[] pin;
    private final Provider provider;

    public HsmKeyProvider(String configPath, char[] pin) throws Exception {
        this.pin = pin;
        this.provider = Security.getProvider("SunPKCS11").configure(configPath);
        Security.addProvider(this.provider);
        this.keyStore = KeyStore.getInstance("PKCS11", this.provider);
        this.keyStore.load(null, pin);
    }

    public PrivateKey getPrivateKey(String label) throws Exception {
        PrivateKey key = (PrivateKey) keyStore.getKey(label, pin);
        if (key == null) {
            throw new IllegalStateException("No private key in HSM with label: " + label);
        }
        return key;
    }

    public PublicKey getPublicKey(String label) throws Exception {
        return getCertificate(label).getPublicKey();
    }

    public X509Certificate getCertificate(String label) throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(label);
        if (cert == null) {
            throw new IllegalStateException("No certificate in HSM with label: " + label);
        }
        return cert;
    }

    public Provider getProvider() {
        return provider;
    }
}
