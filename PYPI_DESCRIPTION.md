# BMAuth - Biometric Authentication for FastAPI

[![PyPI version](https://badge.fury.io/py/bmauth.svg)](https://badge.fury.io/py/bmauth)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure, modern biometric authentication system for FastAPI applications using WebAuthn/FIDO2 standards.

## Features

- 🔐 **WebAuthn/FIDO2 Compliance** - Industry-standard biometric authentication
- 📱 **Cross-Device Support** - Works on phones, tablets, and computers
- ✉️ **Email Verification** - Secure PIN-based email verification
- 🚀 **FastAPI Integration** - Easy integration with FastAPI applications
- 🛡️ **Security First** - Multiple layers of security protection
- 📧 **SendGrid Support** - Built-in email provider integration

## Quick Start

### Installation

```bash
pip install bmauth
```

### Basic Usage

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

# Your app is now ready with biometric authentication!
```

### Available Endpoints

- `GET /auth/register` - Registration page
- `GET /auth/login` - Login page
- `GET /auth/verify` - Email verification page
- `POST /auth/register/begin` - Start registration process
- `POST /auth/register/complete` - Complete registration
- `POST /auth/login/begin` - Start login process
- `POST /auth/login/complete` - Complete login
- `POST /auth/verify-email` - Verify email with PIN
- `POST /auth/resend-pin` - Resend verification PIN

## How It Works

### Registration Flow
1. User provides email address
2. User completes biometric registration (fingerprint, face, etc.)
3. System sends verification PIN via email
4. User verifies email with PIN
5. Account is ready to use

### Authentication Flow
1. User provides email address
2. System generates challenge for biometric verification
3. User completes biometric authentication
4. System verifies the biometric signature
5. User is authenticated

## Requirements

- Python 3.8+
- FastAPI
- SendGrid account (for email verification)

## Documentation

For detailed documentation, examples, and advanced usage, visit our [GitHub repository](https://github.com/samimelhem/bmauth).

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/samimelhem/bmauth/blob/main/LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

- 📧 Email: SaMiLMelhem23@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/samimelhem/bmauth/issues)
- 📖 Documentation: [GitHub Repository](https://github.com/samimelhem/bmauth)
