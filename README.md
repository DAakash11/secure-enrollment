# Secure Device Enrollment & Firmware Signing Service

A Java-based service that models how devices are provisioned with cryptographic
identities and served signed firmware — with the Certificate Authority's private
key protected inside a Hardware Security Module (HSM). Inspired by real
device-provisioning and image-signing pipelines.

> **Status:** Actively developed as a study/portfolio project. The cryptographic
> core (PKI + HSM), token-based authentication, and a device-management (CRUD)
> API are complete and tested.

---

## What it demonstrates

- **PKI** — a Certificate Authority that issues X.509 device certificates from
  Certificate Signing Requests (CSRs), with a verifiable chain of trust.
- **HSM integration** — the CA's private key is generated **inside** a SoftHSM2
  token and is **never extractable**. Signing happens in the token; the key
  never enters application memory.
- **PKCS#11 / JCA-JCE** — the HSM is accessed through Java's `SunPKCS11`
  provider and the standard `KeyStore` / `Signature` APIs.
- **Token-based authentication** — a login endpoint issues short-lived JWTs
  signed with the **same HSM-protected key** (ES256); the API is stateless and
  protected by a token-validation filter.
- **Device management API** — a REST CRUD service over PostgreSQL for managing a
  device fleet (enroll, list, update status, revoke), with a clean four-layer
  architecture and proper HTTP semantics.
- **Applied cryptography** — SHA-256, HMAC-SHA256, Base64 / Base64URL, hex —
  each verified against official test vectors (RFC 4231, standard SHA-256
  vectors).

---

## Architecture

**Certificate issuance (HSM-backed):**

```
Device                      Service (Spring Boot)                 SoftHSM2 Token
------                      ---------------------                 --------------
generate keypair
build CSR  ---------------> CertificateAuthority
(sign with own key)         - verify CSR signature
                            - build leaf certificate
                            - sign leaf  ---------------------->  CA private key
                                                                  (never leaves)
       leaf certificate <-- issued cert  <--------------------- signature only
verify against root CA
```

**Authentication (stateless, HSM-signed tokens):**

```
POST /auth/login (username + password)
      |
      +--> verify credentials (BCrypt)
      +--> mint JWT, signed ES256 inside the HSM  --> returns token

Every /api/** request:  Authorization: Bearer <token>
      |
      +--> JwtAuthFilter verifies signature (HSM public key) + expiry
      +--> request proceeds as the authenticated user
```

**Device management (layered):**

```
HTTP --> Controller --> Service --> Repository --> PostgreSQL
         (REST,         (business    (Spring Data
          status codes)  rules)       JPA)
             |
             +-> @RestControllerAdvice (RFC 7807 error responses)
```

The CA holds only a **handle** to its private key (a `java.security.PrivateKey`
backed by PKCS#11). All signing — certificates and tokens — is delegated to the
HSM.

---

## Tech stack

| Area | Choice |
|------|--------|
| Language / runtime | Java 21 (LTS) |
| Framework | Spring Boot 4.x, Spring Security |
| Cryptography | BouncyCastle (`bcprov`, `bcpkix`), Java JCA/JCE |
| Tokens | Nimbus JOSE+JWT (ES256) |
| HSM | SoftHSM2 via PKCS#11 (`SunPKCS11` provider) |
| Persistence | PostgreSQL + Spring Data JPA |
| Build | Maven |
| Tests | JUnit 5, Mockito, Spring MockMvc |

---

## Project layout

```
src/main/java/com/aakash/qsec/
├── crypto/    # Hashing, HMAC, encoding utilities (verified vs test vectors)
├── ca/        # CertificateAuthority — CSR verification & certificate issuance
├── hsm/       # HsmKeyProvider (PKCS#11 access) + HsmInit (one-time key setup)
├── auth/      # JWT service, login endpoint, token-validation filter
├── device/    # Device entity, repository, service, controller, error handling
└── ...        # Spring Security config
postman/       # Importable Postman collection for the API
```

---

## Authentication

```
POST /auth/login    { "username": "...", "password": "..." }   -> { "token": "..." }
```

The returned token is a JWT signed with **ES256 using the HSM key**. Send it on
every subsequent request:

```
Authorization: Bearer <token>
```

Tokens are short-lived (15 minutes). The server verifies each token's signature
with the HSM's **public** key — signing requires the HSM, verifying does not.

---

## Device API

All endpoints require a valid JWT.

| Method | Path | Purpose | Success |
|--------|------|---------|---------|
| `POST` | `/api/devices` | Register a device | 201 Created |
| `GET` | `/api/devices` | List all devices | 200 OK |
| `GET` | `/api/devices/{id}` | Get one device | 200 OK |
| `PATCH` | `/api/devices/{id}/status` | Update status | 200 OK |
| `DELETE` | `/api/devices/{id}` | Remove a device | 204 No Content |

Errors follow **RFC 7807 (Problem Details)**: a missing device returns
`404 Not Found`; a duplicate serial or an illegal status change (e.g.
reactivating a revoked device) returns `409 Conflict`.

**Domain rules enforced in the service layer:**
- Serial numbers are unique — duplicates are rejected.
- A `REVOKED` device is terminal and cannot change status.

A ready-to-run **Postman collection** is included under `postman/`. Import it,
set `baseUrl` to `http://localhost:8080`, run the login request, and the token
is captured automatically for the other requests.

---

## Security design notes

- **Key never leaves the HSM.** The CA/signing key is generated in-token with the
  `never-extractable` and `always-sensitive` attributes set; verified directly
  with `pkcs11-tool` (the private key cannot be read out even with the User PIN).
- **One protected key, two uses.** The same HSM key signs both X.509 certificates
  and JWTs — signing happens inside the token in both cases.
- **Proof of possession.** Before issuing a certificate, the CA verifies the
  CSR's own signature — proving the requester holds the private key matching the
  public key being certified.
- **Stateless auth.** No server-side sessions; each request carries a signed
  token. Passwords are checked only once, at login (BCrypt), not on every call.
- **Certificate hierarchy.** The root is a CA (`basicConstraints: CA=true`,
  long-lived); issued leaves are not CAs (`CA=false`) and are short-lived
  (90 days).
- **No secrets in source control.** The database password and HSM PIN are
  supplied via environment variables (`${DB_PASSWORD}`, `${HSM_PIN}`); the HSM
  PKCS#11 config contains no secrets. Private key material and PEM/PKCS#12 files
  are gitignored.
- **CSRF disabled deliberately.** The API is stateless and token-based, not
  cookie-session based, so CSRF (a cookie-riding attack) does not apply.

---

## Testing

Tests are separated by type, chosen to match what each layer does:

- **Unit tests** — the crypto utilities (against published vectors such as
  RFC 4231), and the device service's business rules, tested in isolation with a
  mocked repository (Mockito).
- **Integration tests** — the HSM access layer and Certificate Authority, which
  exercise the real SoftHSM token through PKCS#11; and the REST controller via
  `@WebMvcTest` + MockMvc, verifying routing, JSON handling, status codes, and
  exception-to-HTTP mapping.

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
- [x] Device management (CRUD) over PostgreSQL, with tests
- [x] JWT authentication with HSM-signed (ES256) tokens
- [ ] mTLS device enrollment endpoint (client certs issued by the CA)
- [ ] Firmware manifest signing endpoint + device-side verifier
- [ ] Certificate revocation (CRL)

---

## Notes

This is a reference/study implementation, not a production system. SoftHSM2
stands in for a physical HSM (both speak PKCS#11, so the application code is the
same). A production deployment would use a certified HSM, managed database
migrations, OCSP for revocation, and secrets managed outside the application.
