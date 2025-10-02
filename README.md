# BMAuth
Biometric Authentication System for FastAPI applications, providing the most secure authentication system to any developer. 

This system leverages WebAuthn/FIDO2 Principles in building lots of secure layers, while being a smooth experience for users.

## Installation

Install BMAuth directly from PyPI:

```bash
pip install bmauth
```

## Quick Start

```python
from fastapi import FastAPI
from bmauth import BMAuth

app = FastAPI()

# Initialize BMAuth
auth = BMAuth(
    app=app,
    email_api_key="your-sendgrid-api-key",
    from_email="noreply@yourdomain.com"
)

# Your app now has biometric authentication endpoints!
```

## Registering
- User types in email (identifier in the server)
- User provides biometric (establishes device's private key) and sends public key to the server
- Server registers user and asks to verify email via Email PIN
- User enters the PIN and is brought to the application
    - Email is marked as verified

## Authenticating
- User provides email (sent to server), server verifies user trying to sign in on the same device, server sends back a random challenge to the user
- User gives device biometrics to solve the challenge (private key creates a digital signature), sends the response to the server
- Server verifies the signature with the public key, and brings the user to the application

## Different Device Authentication
### Adding a new device via Cross-Verification
- Device B initiates login
- Verify on Device A
    - Phone/Tablet: QR Code to verify biometrically will come from Laptop/Computer
    - Laptop/Computer: Sign into the application, scan the QR Code “Scan this with your new device to approve the sign-in”, then laptop/computer biometric verification
        - The phone/tablet will say “To sign in, go to yourapp.com/link on your already-registered computer”, and then open up the camera view to scan for the QR Code
        - Note: Requires developer to input the link to their app when creating their authentication
- Device B is verified (Creates a private key and sends public key to the server)
- Device B is now registered
### Account Recovery
- Device B would click on “Lost my device” or “Can’t approve?”
- Server sends an Email PIN to device B
- Device B is verified (Creates a private key and sends public key to the server)
- Device B is registered
- User is prompted to de-authorize the lost Device A for security purposes