"""
Core BMAuth authentication class
"""
from typing import Optional
from pathlib import Path
import secrets
import base64
import time
import hashlib
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse, Response
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


class JoinDeviceRequest(BaseModel):
    session_id: str
    credential: dict


# Temporary in-memory storage (replace with database)
users_db = {}
challenges_db = {}
verification_pins = {}
add_device_sessions = {}


def detect_device_info(user_agent: str) -> dict:
    """
    Parse User-Agent to detect device type and generate friendly name

    Args:
        user_agent: HTTP User-Agent header string

    Returns:
        dict with device_type ("mobile" | "desktop"), device_name, os, and browser
    """
    ua_lower = user_agent.lower()

    # Detect mobile vs desktop
    is_mobile = any(x in ua_lower for x in [
        'mobile', 'android', 'iphone', 'ipad',
        'ipod', 'blackberry', 'windows phone'
    ])

    device_type = "mobile" if is_mobile else "desktop"

    # Parse browser
    if 'chrome' in ua_lower and 'edg' not in ua_lower:
        browser = "Chrome"
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        browser = "Safari"
    elif 'firefox' in ua_lower:
        browser = "Firefox"
    elif 'edg' in ua_lower:
        browser = "Edge"
    else:
        browser = "Browser"

    # Parse OS and device
    if 'iphone' in ua_lower:
        os_name = "iPhone"
    elif 'ipad' in ua_lower:
        os_name = "iPad"
    elif 'android' in ua_lower:
        os_name = "Android"
    elif 'macintosh' in ua_lower or 'mac os x' in ua_lower:
        os_name = "MacBook" if 'macbook' in ua_lower else "Mac"
    elif 'windows' in ua_lower:
        os_name = "Windows PC"
    elif 'linux' in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Device"

    return {
        "device_type": device_type,
        "device_name": f"{browser} on {os_name}",
        "os": os_name,
        "browser": browser
    }


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
                    "name": "BMAuth"
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
            cred: RegistrationCredential, background_tasks: BackgroundTasks, request: Request
        ):
            """Complete registration - store public key and send verification email"""
            email = cred.email

            # Verify challenge exists
            if email not in challenges_db:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Detect device info
            user_agent = request.headers.get("user-agent", "")
            device_info = detect_device_info(user_agent)
            device_id = hashlib.sha256(f"{email}:{user_agent}".encode()).hexdigest()

            # Store user with multi-device structure
            users_db[email] = {
                "email_verified": False,
                "devices": {
                    device_id: {
                        "credential_id": cred.credential.get("id"),
                        "public_key": cred.credential.get("response", {}).get("publicKey"),
                        "device_name": device_info["device_name"],
                        "device_type": device_info["device_type"],
                        "registered_at": time.time(),
                        "last_used": time.time()
                    }
                }
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
        async def login_begin(req: LoginRequest, request: Request):
            """Begin login - check if THIS device is registered"""
            email = req.email

            # Check if user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # Auto-migrate old schema to new multi-device structure
            if "credential_id" in users_db[email]:  # Old single-device schema
                user_agent = request.headers.get("user-agent", "")
                device_info = detect_device_info(user_agent)
                device_id = hashlib.sha256(f"{email}:{user_agent}".encode()).hexdigest()

                old_data = users_db[email]
                users_db[email] = {
                    "email_verified": old_data.get("email_verified", False),
                    "devices": {
                        device_id: {
                            "credential_id": old_data["credential_id"],
                            "public_key": old_data["public_key"],
                            "device_name": device_info["device_name"],
                            "device_type": device_info["device_type"],
                            "registered_at": old_data.get("created_at", time.time()),
                            "last_used": time.time()
                        }
                    }
                }

            # Detect current device
            user_agent = request.headers.get("user-agent", "")
            device_info = detect_device_info(user_agent)
            device_id = hashlib.sha256(f"{email}:{user_agent}".encode()).hexdigest()

            # Check if THIS specific device is registered
            user_devices = users_db[email]["devices"]
            is_this_device_registered = device_id in user_devices

            if not is_this_device_registered:
                # Device not registered - show message to scan QR from registered device
                return JSONResponse({
                    "registered": False,
                    "message": "This device is not registered. Please scan the QR code from a registered device.",
                    "device_info": device_info
                })

            # Device IS registered - proceed with normal login
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.b64encode(challenge).decode('utf-8')
            challenges_db[email] = challenge_b64

            user_device = user_devices[device_id]

            return JSONResponse({
                "registered": True,
                "challenge": challenge_b64,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": user_device["credential_id"]
                }],
                "userVerification": "required",
                "timeout": 60000
            })

        @self.app.post("/auth/login/complete")
        async def login_complete(cred: LoginCredential, request: Request):
            """Complete login - verify signature and create QR session"""
            email = cred.email

            # Verify challenge exists
            if email not in challenges_db:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Verify user exists
            if email not in users_db:
                return JSONResponse({"error": "User not found"}, status_code=404)

            # Detect current device
            user_agent = request.headers.get("user-agent", "")
            device_id = hashlib.sha256(f"{email}:{user_agent}".encode()).hexdigest()

            # In production, verify the signature with the stored public key
            # For now, basic validation
            user_devices = users_db[email]["devices"]
            if device_id not in user_devices:
                return JSONResponse({"error": "Device not registered"}, status_code=401)

            stored_credential_id = user_devices[device_id]["credential_id"]
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

            # Update last_used for this device
            users_db[email]["devices"][device_id]["last_used"] = time.time()

            # Create QR session automatically
            session_id = secrets.token_urlsafe(32)
            add_device_sessions[session_id] = {
                "email": email,
                "expires_at": time.time() + 300,  # 5 minutes
                "status": "pending",
                "new_device_id": None
            }

            return JSONResponse({
                "success": True,
                "message": "Login successful",
                "user": {"email": email},
                "qr_session_id": session_id
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

        @self.app.get("/auth/qr/{session_id}")
        async def generate_qr(session_id: str):
            """Generate QR code PNG for device registration"""
            import qrcode
            from io import BytesIO

            if session_id not in add_device_sessions:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Generate QR code with join URL
            join_url = f"https://{self.host}/auth/device/join/{session_id}"
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(join_url)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            buf = BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)

            return Response(content=buf.getvalue(), media_type="image/png")

        @self.app.get("/auth/device/poll/{session_id}")
        async def poll_device_status(session_id: str):
            """Desktop polls to check if new device was added"""
            if session_id not in add_device_sessions:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            session = add_device_sessions[session_id]

            # Check expiration
            if time.time() > session["expires_at"]:
                del add_device_sessions[session_id]
                return JSONResponse({"error": "Session expired"}, status_code=400)

            if session["status"] == "completed":
                device_id = session["new_device_id"]
                email = session["email"]
                device_name = users_db[email]["devices"][device_id]["device_name"]

                return JSONResponse({
                    "status": "completed",
                    "new_device_name": device_name
                })

            return JSONResponse({"status": "pending"})

        @self.app.get("/auth/device/join/{session_id}", response_class=HTMLResponse)
        async def join_device_page(session_id: str, request: Request):
            """Page shown when phone scans QR code"""
            if session_id not in add_device_sessions:
                return HTMLResponse("<h2>Invalid or expired session</h2>", status_code=400)

            join_html = templates_dir / "join_device.html"
            return HTMLResponse(content=join_html.read_text(encoding='utf-8'), status_code=200)

        @self.app.post("/auth/device/join/begin/{session_id}")
        async def join_device_begin(session_id: str, request: Request):
            """Get WebAuthn registration options for new device"""
            if session_id not in add_device_sessions:
                return JSONResponse({"error": "Invalid or expired session"}, status_code=400)

            session = add_device_sessions[session_id]
            email = session["email"]

            # Generate challenge
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.b64encode(challenge).decode('utf-8')
            challenges_db[email] = challenge_b64

            return JSONResponse({
                "challenge": challenge_b64,
                "rp": {
                    "name": "BMAuth"
                },
                "user": {
                    "id": base64.b64encode(email.encode()).decode('utf-8'),
                    "name": email,
                    "displayName": email
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
                "timeout": 60000,
                "attestation": "none"
            })

        @self.app.post("/auth/device/join/complete")
        async def join_device_complete(req: JoinDeviceRequest, request: Request):
            """Complete device registration via QR scan"""
            session_id = req.session_id

            if session_id not in add_device_sessions:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            session = add_device_sessions[session_id]
            email = session["email"]

            # Detect new device
            user_agent = request.headers.get("user-agent", "")
            device_info = detect_device_info(user_agent)
            device_id = hashlib.sha256(f"{email}:{user_agent}".encode()).hexdigest()

            # Store new device
            users_db[email]["devices"][device_id] = {
                "credential_id": req.credential.get("id"),
                "public_key": req.credential.get("response", {}).get("publicKey"),
                "device_name": device_info["device_name"],
                "device_type": device_info["device_type"],
                "registered_at": time.time(),
                "last_used": time.time()
            }

            # Update session
            session["status"] = "completed"
            session["new_device_id"] = device_id

            return JSONResponse({
                "success": True,
                "device_name": device_info["device_name"]
            })

        @self.app.get("/auth/status")
        async def status():
            """Check authentication status"""
            return JSONResponse({"status": "BMAuth active"})