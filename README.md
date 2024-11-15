
# Custom RSA and Certificate Authority Implementation

This Python project includes a basic attempt at RSA cryptography and a certificate authority simulation, is in no way cryptographically safe, might want to increase Mersenne Twister state sise for bigger RSA keys to avoid a potential infinite loop.
The Client Object needs a reference to the CA object because of the addition of a CRL. This is to keep the CRL private, this would normally be a call to the CA. In a world where the CRL is public, or certificate revokation is not allowed, this call would not be needed.
AES and SHA-256 implementations are not mine.

## Implementation Details

### `crsa.py` - RSA Cryptography

- **Key Generation**:
  - Generates random numbers with a custom implementation of the Mersenne Twister.
  - Implements extended Euclidean algorithm to calculate modular inverses for key generation.
  - Supports PEM.
  - Can encrypt and decrypt messages.

### `cert_auth.py` - Certificate Authority Simulation

- **RSA Signature and Verification**:
  - Generates and signs certificate requests.
  - Verifies and revokes generated certificates.

## How to Use

### RSA Key Generation and Message Encryption/Decryption:

```python
from crsa import RSA, Key

# Generate RSA keys
p, q, d, e, n, private_pem, public_pem = RSA.keygen(1024)

print("Generated Private Key PEM:")
print(private_pem)
print("Generated Public Key PEM:")
print(public_pem)

# Create RSA objects from PEM
private_rsa_crypt = RSA.from_pem(Key.PRIVATE, private_pem)
public_rsa_crypt = RSA.from_pem(Key.PUBLIC, public_pem)

# Encrypt a message
print("Encrypting message...")
encrypted = public_rsa_crypt.encrypt("Hello, World!")
print(encrypted + "\n")

# Decrypt the message
print("Decrypting message...")
decrypted = private_rsa_crypt.decrypt(encrypted) + "\n"
print(decrypted)
```

### Certificate Authority and Certificate Management:

```python
from cert_auth import CertAuth, CertClient
import json

# Create a Certificate Authority
print("Creating Certificate Authority...")
auth_mic = CertAuth(common_name='AuthServer')
print(auth_mic.common_name + "\n")
print(json.dumps(auth_mic.certificate, indent=4, default=str))

# Create a Client and generate a CSR
print("Creating Client Certificate...")
client_mic = CertClient(common_name='Company')
print(client_mic.common_name + "\n")

print("Generating CSR...")
com_csr = client_mic.generate_csr()
print(json.dumps(com_csr, indent=4, default=str) + "\n")

# CA generates a certificate from the CSR
print("Generating Certificate...")
com_cert = auth_mic.generate_certificate(com_csr)
print(json.dumps(com_cert, indent=4, default=str) + "\n")

# Assign the certificate to the client
client_mic.assign_certificate(com_cert)

# Verify the certificate before revocation
print("Verifying Certificate before revocation...")
validity = CertClient.verify_certificate(client_mic.certificate["issuer"]["common_name"], client_mic.certificate)
print("Certificate is valid!" if validity else "Certificate is invalid.")

# Revoke the certificate
print("\nRevoking Certificate...")
auth_mic.revoke_certificate(com_cert['serial_number'])

# Verify the certificate after revocation
print("Verifying Certificate after revocation...")
validity_post_revocation = CertClient.verify_certificate(client_mic.certificate["issuer"]["common_name"], client_mic.certificate)
print("Certificate is valid!" if validity_post_revocation else "Certificate is invalid.")
```
