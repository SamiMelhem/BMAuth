"""
Core BMAuth authentication class
"""
from typing import Optional
from pathlib import Path
import secrets
import base64
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    email: str


class RegistrationCredential(BaseModel):
    email: str
    credential: dict


# Temporary in-memory storage (replace with database)
users_db = {}
challenges_db = {}


class BMAuth:
    """
    Biometric Authentication System for FastAPI
    """

    def __init__(self, app: Optional[FastAPI] = None, host: str = "localhost", port: int = 8000):
        """
        Initialize BMAuth

        Args:
            app: Optional FastAPI application instance
        """
        self.app = app
        self.host = host
        self.port = port
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
        async def register_complete(cred: RegistrationCredential):
            """Complete registration - store public key"""
            email = cred.email

            # Verify challenge exists
            if email not in challenges_db:
                return JSONResponse({"error": "Invalid session"}, status_code=400)

            # Store user credential (public key)
            users_db[email] = {
                "credential_id": cred.credential.get("id"),
                "public_key": cred.credential.get("response", {}).get("publicKey"),
                "counter": 0
            }

            # Clean up challenge
            del challenges_db[email]

            return JSONResponse({"success": True, "message": "Registration successful"})

        @self.app.get("/auth/status")
        async def status():
            """Check authentication status"""
            return JSONResponse({"status": "BMAuth active"})