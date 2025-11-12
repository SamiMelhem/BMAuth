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


## Local Development & Cross-Device Testing

BMAuth ships with a helper command that spins up the demo FastAPI app and exposes it over HTTPS using [LocalTunnel](https://github.com/localtunnel/localtunnel). This lets a phone or tablet hit the same WebAuthn flow as your laptop without configuring certificates or paid tunnelling services.

### Prerequisites
- Python dev dependencies: `pip install -e .[dev]`
- Node.js 16+ (ships with `npx`)
- Optional (faster startup): `npm install -g localtunnel`

### Start the tunnelled dev server

```bash
bmauth-dev-tunnel
```

The command:
1. launches `uvicorn` on `http://127.0.0.1:8000`
2. opens a LocalTunnel session and prints an `https://<random>.loca.lt` URL
3. sets the WebAuthn relying-party host automatically so QR codes and login flows use the secure tunnel

Point your desktop browser at the local URL and scan the printed public URL with your mobile device. When you stop the command (`Ctrl+C`), both the tunnel and the dev server shut down.

You can customise the behaviour:

```bash
bmauth-dev-tunnel --app mypackage.main:app --port 9000 --subdomain mycustomname -- --reload
```

The flags after `--` are forwarded directly to `uvicorn`.

If you prefer to run your own tunnel or reverse proxy, set `BMAUTH_HOST` before starting your app; the sample `tests/test_app.py` will use that value when constructing QR codes and WebAuthn challenges.
