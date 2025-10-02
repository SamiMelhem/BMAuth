"""
Core BMAuth authentication class
"""
from typing import Optional
from pathlib import Path
import secrets
import base64
import time
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from .email_providers import EmailProvider, SendGridProvider


class RegisterRequest(BaseModel):
    email: str


class RegistrationCredential(BaseModel):
    email: str
    credential: dict


class LoginRequest(BaseModel):
    email: str


class LoginCredential(BaseModel):
    email: str
    credential: dict


class VerifyEmailRequest(BaseModel):
    email: str
    pin: str


class ResendPinRequest(BaseModel):
    email: str


# Temporary in-memory storage (replace with database)
users_db = {}
challenges_db = {}
verification_pins = {}


class BMAuth:
    """
    Biometric Authentication System for FastAPI
    """

    def __init__(
        self,
        app: Optional[FastAPI] = None,
        host: str = "localhost",
        port: int = 8000,
        email_api_key: Optional[str] = None,
        from_email: Optional[str] = None,
    ):
        """
        Initialize BMAuth

        Args:
            app: Optional FastAPI application instance
            host: Host for WebAuthn (default: localhost)
            port: Port for server (default: 8000)
            email_api_key: SendGrid API key
            from_email: Sender email address (must be verified in SendGrid)
        """
        self.app = app
        self.host = host
        self.port = port

        # Initialize SendGrid email provider
        self.email_provider_instance: Optional[EmailProvider] = None
        if email_api_key and from_email:
            self.email_provider_instance = SendGridProvider(email_api_key, from_email)
        else:
            print(
                "Warning: Email provider not configured. Email verification will not work."
            )

        if app is not None:
            self.init_app(app)

    def init_app(self, app: FastAPI):
        """
        Initialize the FastAPI application with BMAuth routes

        Args:
            app: FastAPI application instance
        """
        self.app = app
        self._register_routes()

    def _generate_pin(self) -> str:
        """Generate a random 6-digit PIN"""
        return str(secrets.randbelow(1000000)).zfill(6)

    def _is_pin_valid(self, email: str, pin: str) -> bool:
        """Validate PIN for given email"""
        if email not in verification_pins:
            return False

        pin_data = verification_pins[email]

        # Check if PIN expired (10 minutes)
        if time.time() > pin_data["expires_at"]:
            del verification_pins[email]
            return False

        # Check max attempts (3)
        if pin_data["attempts"] >= 3:
            return False

        # Increment attempts
        pin_data["attempts"] += 1

        # Check if PIN matches
        if pin_data["pin"] == pin:
            del verification_pins[email]  # Single use
            return True

        return False

    async def _send_verification_email(self, email: str, pin: str) -> bool:
        """Send verification email with PIN"""
        if not self.email_provider_instance:
            print("BMAuth: Email provider not configured")
            return False

        subject = "Verify Your Email - BMAuth"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0;">🔐 Verify Your Email</h1>
            </div>
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
                <p style="font-size: 16px;">Your verification PIN is:</p>
                <div style="background: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea;">{pin}</span>
                </div>
                <p style="font-size: 14px; color: #666;">This PIN will expire in <strong>10 minutes</strong>.</p>
                <p style="font-size: 14px; color: #666;">If you didn't request this verification, please ignore this email.</p>
            </div>
            <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                <p>Powered by BMAuth - Biometric Authentication System</p>
            </div>
        </body>
        </html>
        """

        return await self.email_provider_instance.send_email(
            to_email=email, subject=subject, html_content=html_content
        )

    def _register_routes(self):
        """Register authentication routes"""
        templates_dir = Path(__file__).parent / "templates"

        @self.app.get("/auth/register", response_class=HTMLResponse)
        async def register(request: Request):
            """Register a new user"""
            register_html = templates_dir / "register.html"
            return HTMLResponse(content=register_html.read_text(encoding='utf-8'), status_code=200)

        @self.app.get("/auth/login", response_class=HTMLResponse)
        async def login(request: Request):
            """Authenticate user"""
            login_html = templates_dir / "login.html"
            return HTMLResponse(content=login_html.read_text(encoding='utf-8'), status_code=200)

        @self.app.get("/auth/verify", response_class=HTMLResponse)
        async def verify(request: Request):
            """Email verification page"""
            verify_html = templates_dir / "verify.html"
            return HTMLResponse(content=verify_html.read_text(encoding='utf-8'), status_code=200)

        @self.app.post("/auth/register/begin")
        async def register_begin(req: RegisterRequest):
            """Begin registration - generate challenge for WebAuthn"""
            # Generate random challenge
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.b64encode(challenge).decode('utf-8')

            # Store challenge temporarily
            challenges_db[req.email] = challenge_b64

            return JSONResponse({
                "challenge": challenge_b64,
                "rp": {
                    "name": "BMAuth",
                    "id": self.host
                },
                "user": {
                    "id": base64.b64encode(req.email.encode()).decode('utf-8'),
                    "name": req.email,
                    "displayName": req.email
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},   # ES256
                    {"type": "public-key", "alg": -257}  # RS256
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "requireResidentKey": False,
                    "userVerification": "required"
                },
                "timeout": 60000,  # 60 seconds
                "attestation": "none"
            })

        @self.app.post("/auth/register/complete")
        async def register_complete(
            cred: RegistrationCredential, background_tasks: BackgroundTasks
        ):
            """Complete registration - store public key and send verification email"""
            email = cred.email

            # Verify challenge exists
            if email not in challenges_db:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Store user credential (public key) with email_verified = False
            users_db[email] = {
                "credential_id": cred.credential.get("id"),
                "public_key": cred.credential.get("response", {}).get("publicKey"),
                "counter": 0,
                "email_verified": False,
                "created_at": time.time(),
            }

            # Clean up challenge
            del challenges_db[email]

            # Generate PIN and store with expiration
            pin = self._generate_pin()
            verification_pins[email] = {
                "pin": pin,
                "expires_at": time.time() + 600,  # 10 minutes
                "attempts": 0,
                "last_sent": time.time(),
            }

            # Send verification email in background (non-blocking)
            background_tasks.add_task(self._send_verification_email, email, pin)

            return JSONResponse(
                {
                    "success": True,
                    "message": "Registration successful. Please check your email for verification PIN.",
                    "email": email,
                }
            )

        @self.app.post("/auth/login/begin")
        async def login_begin(req: LoginRequest):
            """Begin login - generate challenge for WebAuthn"""
            email = req.email

            # Check if user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # Generate random challenge
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.b64encode(challenge).decode('utf-8')

            # Store challenge temporarily
            challenges_db[email] = challenge_b64

            user = users_db[email]

            return JSONResponse({
                "challenge": challenge_b64,
                "rpId": self.host,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": user["credential_id"]
                }],
                "userVerification": "required",
                "timeout": 60000
            })

        @self.app.post("/auth/login/complete")
        async def login_complete(cred: LoginCredential):
            """Complete login - verify signature"""
            email = cred.email

            # Verify challenge exists
            if email not in challenges_db:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Verify user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # In production, verify the signature with the stored public key
            # For now, basic validation
            stored_credential_id = users_db[email]["credential_id"]
            received_credential_id = cred.credential.get("id")

            if stored_credential_id != received_credential_id:
                return JSONResponse({"error": "Invalid credential"}, status_code=401)

            # Clean up challenge
            del challenges_db[email]

            # Check if email is verified
            if not users_db[email].get("email_verified", False):
                return JSONResponse(
                    {"error": "Email not verified. Please verify your email first."},
                    status_code=403,
                )

            return JSONResponse({
                "success": True,
                "message": "Login successful",
                "user": {"email": email}
            })

        @self.app.post("/auth/verify-email")
        async def verify_email(req: VerifyEmailRequest):
            """Verify email with PIN"""
            email = req.email
            pin = req.pin

            # Check if user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # Check if already verified
            if users_db[email].get("email_verified", False):
                return JSONResponse(
                    {"success": True, "message": "Email already verified"}
                )

            # Validate PIN
            if not self._is_pin_valid(email, pin):
                return JSONResponse(
                    {"error": "Invalid or expired PIN"}, status_code=400
                )

            # Mark email as verified
            users_db[email]["email_verified"] = True

            return JSONResponse(
                {"success": True, "message": "Email verified successfully"}
            )

        @self.app.post("/auth/resend-pin")
        async def resend_pin(req: ResendPinRequest, background_tasks: BackgroundTasks):
            """Resend verification PIN"""
            email = req.email

            # Check if user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # Check if already verified
            if users_db[email].get("email_verified", False):
                return JSONResponse(
                    {"error": "Email already verified"}, status_code=400
                )

            # Rate limiting: Check if last sent was less than 1 minute ago
            if email in verification_pins:
                last_sent = verification_pins[email].get("last_sent", 0)
                if time.time() - last_sent < 60:
                    return JSONResponse(
                        {"error": "Please wait before requesting a new PIN"},
                        status_code=429,
                    )

            # Generate new PIN
            pin = self._generate_pin()
            verification_pins[email] = {
                "pin": pin,
                "expires_at": time.time() + 600,  # 10 minutes
                "attempts": 0,
                "last_sent": time.time(),
            }

            # Send email in background
            background_tasks.add_task(self._send_verification_email, email, pin)

            return JSONResponse(
                {"success": True, "message": "New verification PIN sent to your email"}
            )

        @self.app.get("/auth/status")
        async def status():
            """Check authentication status"""
            return JSONResponse({"status": "BMAuth active"})