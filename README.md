# Secure Device Enrollment & Firmware Signing Service

A Java-based service that models how devices are provisioned with cryptographic
identities and served signed firmware — with the Certificate Authority's private
key protected inside a Hardware Security Module (HSM). Inspired by real
device-provisioning and image-signing pipelines.

> **Status:** Actively developed as a study/portfolio project. The cryptographic
> core (PKI + HSM) is complete and tested; a device-management (CRUD) layer is
> in progress.

---

## What it demonstrates

- **PKI** — a Certificate Authority that issues X.509 device certificates from
  Certificate Signing Requests (CSRs), with a verifiable chain of trust.
- **HSM integration** — the CA's private key is generated **inside** a SoftHSM2
  token and is **never extractable**. Signing happens in the token; the key
  never enters application memory.
- **PKCS#11 / JCA-JCE** — the HSM is accessed through Java's `SunPKCS11`
  provider and the standard `KeyStore` / `Signature` APIs.
- **Authentication & authorization** — Spring Security with custom users, roles,
  and BCrypt-hashed credentials.
- **Applied cryptography** — SHA-256, HMAC-SHA256, Base64 / Base64URL, hex —
  each verified against official test vectors (RFC 4231, standard SHA-256
  vectors).

---

## Architecture

```
Device                      Service (Spring Boot)                 SoftHSM2 Token
------                      ---------------------                 --------------
generate keypair
build CSR  ───────────────► CertificateAuthority
(sign with own key)         - verify CSR signature
                            - build leaf certificate
                            - sign leaf  ──────────────────────►  CA private key
                                                                  (never leaves)
       leaf certificate ◄── issued cert  ◄───────────────────── signature only
verify against root CA
```

Key point: the CA holds only a **handle** to its private key (a
`java.security.PrivateKey` backed by PKCS#11). All signing is delegated to the
HSM.

---

## Tech stack

| Area | Choice |
|------|--------|
| Language / runtime | Java 21 (LTS) |
| Framework | Spring Boot 4.x, Spring Security |
| Cryptography | BouncyCastle (`bcprov`, `bcpkix`), Java JCA/JCE |
| HSM | SoftHSM2 via PKCS#11 (`SunPKCS11` provider) |
| Persistence | PostgreSQL + Spring Data JPA *(CRUD layer, in progress)* |
| Build | Maven |
| Tests | JUnit 5 |

---

## Project layout

```
src/main/java/com/aakash/qsec/
├── crypto/    # Hashing, HMAC, encoding utilities (verified vs test vectors)
├── ca/        # CertificateAuthority — CSR verification & certificate issuance
├── hsm/       # HsmKeyProvider (PKCS#11 access) + HsmInit (one-time key setup)
├── device/    # Device entity + CRUD layer (in progress)
└── ...        # Spring Security config, web endpoints
```

---

## Security design notes

- **Key never leaves the HSM.** The CA key is generated in-token with the
  `never-extractable` and `always-sensitive` attributes set; this was verified
  directly with `pkcs11-tool` (the private key cannot be read out even with the
  User PIN).
- **Proof of possession.** Before issuing a certificate, the CA verifies the
  CSR's own signature — proving the requester holds the private key matching the
  public key being certified.
- **Certificate hierarchy.** The root is a CA (`basicConstraints: CA=true`,
  long-lived); issued leaves are not CAs (`CA=false`) and are short-lived
  (90 days).
- **No secrets in source control.** The database password is supplied via an
  environment variable (`${DB_PASSWORD}`); the HSM PKCS#11 config contains no
  secrets. Private key material and PEM/PKCS#12 files are gitignored.
- **Passwords are hashed.** Application user credentials use BCrypt.

---

## Testing

Tests are separated by type:

- **Unit tests** — the crypto utilities, tested in isolation against published
  test vectors (e.g. RFC 4231 for HMAC).
- **Integration tests** — the HSM access layer and the Certificate Authority,
  which exercise the real SoftHSM token through PKCS#11 and verify that
  HSM-signed certificates chain correctly to the root.

Run all tests:

```bash
./mvnw test
```

---

## Roadmap

- [x] Verified cryptographic primitives (hashing, HMAC, encoding)
- [x] Spring Security with roles and hashed credentials
- [x] Certificate Authority (CSR verification, X.509 issuance, chain of trust)
- [x] HSM integration — CA key generated and used entirely within SoftHSM
- [ ] Device management (CRUD) over PostgreSQL
- [ ] mTLS device enrollment endpoint
- [ ] JWT-based admin authentication
- [ ] Firmware manifest signing endpoint + device-side verifier
- [ ] Certificate revocation (CRL)

---

## Notes

This is a reference/study implementation, not a production system. SoftHSM2
stands in for a physical HSM (both speak PKCS#11, so the application code is the
same). A production deployment would use a certified HSM, managed database
migrations, OCSP for revocation, and secrets managed outside the application.