package com.aakash.qsec.auth;

import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;

import org.springframework.stereotype.Service;

import com.aakash.qsec.hsm.HsmKeyProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JwtService {

    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private static final long VALIDITY_MS = 15 * 60 * 1000; // 15 minutes

    public JwtService(HsmKeyProvider hsm) throws Exception {
        String label = "qsec-ca-key";

        // Signer uses the HSM private key handle (signing happens in the token)
        PrivateKey hsmPrivateKey = hsm.getPrivateKey(label);
        ECDSASigner ecSigner = new ECDSASigner(hsmPrivateKey, com.nimbusds.jose.jwk.Curve.P_256);
        ecSigner.getJCAContext().setProvider(hsm.getProvider()); // route signing through PKCS#11
        this.signer = ecSigner;

        // Verifier uses the public key (readable, no HSM needed to verify)
        ECPublicKey publicKey = (ECPublicKey) hsm.getPublicKey(label);
        this.verifier = new ECDSAVerifier(publicKey);
    }

    // Mint a signed JWT for an authenticated user
    public String issueToken(String username, String role) throws Exception {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + VALIDITY_MS);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .claim("role", role)
                .issuer("qsec-auth")
                .issueTime(now)
                .expirationTime(expiry)
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader(JWSAlgorithm.ES256),
                claims);

        jwt.sign(signer);          // <-- signature produced INSIDE the HSM
        return jwt.serialize();    // <-- the three Base64URL segments joined by dots
    }

    // Validate a token: signature + expiry. Returns the claims if valid.
    public JWTClaimsSet validateToken(String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);

        if (!jwt.verify(verifier)) {
            throw new SecurityException("Invalid JWT signature");
        }

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        if (claims.getExpirationTime().before(new Date())) {
            throw new SecurityException("JWT expired");
        }
        return claims;
    }
}
