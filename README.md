# Secure Device Enrollment & Firmware Signing Service

A study project modelling how devices are provisioned with cryptographic identies and served signed firmware - inspired by real SoC provisioning pipelines.

## What it demonstrates
- **PKI**: a smaill Certificate Authority issuing X.509 device certificates
- **HSM** the CA private key lives inside a SoftHSM2 token (PKCS
- **Authentication**: mTLS for devices, JWT for admins
- **Authorisation**: role-based access (DEVICE / ADMIN / SIGNER)
- **Firmware signing**: signed manifests a device client verifies
- **Encoding*: PEM/DER, Base64URL, JWT, canonical JSON

## Tech stack 
00b7

Java 21

