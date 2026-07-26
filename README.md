# Secure Device Enrollment & Firmware Signing Service

A study project modelling how devices are provisioned with cryptographic
identities and served signed firmware — inspired by real SoC provisioning
pipelines.

## What it demonstrates
- **PKI**: a small Certificate Authority issuing X.509 device certificates
- **HSM**: the CA private key lives inside a SoftHSM2 token (PKCS#11) and never leaves it
- **Authentication**: mTLS for devices, JWT for admins
- **Authorization**: role-based access (DEVICE / ADMIN / SIGNER)
- **Firmware signing**: signed manifests a device client verifies
- **Encoding**: PEM/DER, Base64URL, JWT, canonical JSON

## Tech stack
Java 21 · Spring Boot 3 · Spring Security 6 · BouncyCastle · SoftHSM2

## Status
🚧 In active development — reference implementation, not production.

---
*Built as part of preparing for a security engineering role.*