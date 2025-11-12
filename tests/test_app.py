"""
Test FastAPI app with BMAuth integration + LocalTunnel for mobile testing
"""
from fastapi import FastAPI
from bmauth.auth import BMAuth
import uvicorn
import os
import socket
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# def get_local_ip():
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))
#             return s.getsockname()[0]
#     except OSError:
#         return "localhost"

# Create FastAPI app
app = FastAPI(title="BMAuth Test App")

# Determine host for WebAuthn
host_for_webauthn = os.getenv("BMAUTH_HOST", "localhost")

if host_for_webauthn == "localhost":
    desktop_url = "http://localhost:8000"
    public_url = desktop_url
else:
    desktop_url = "http://127.0.0.1:8000"
    public_url = f"https://{host_for_webauthn}"

print("\n" + "=" * 60)
print("🚀 BMAuth Test App")
print("=" * 60)
print(f"💻 Local Desktop URL: {desktop_url}")
print(f"🌐 Public URL (shareable): {public_url}")
print(f"🔗 WebAuthn RP ID Host: {host_for_webauthn}")
print("=" * 60)
print("\nTesting Instructions:")
print("1. Desktop: Open the local URL in your browser")
print("2. Register with Face ID/Windows Hello")
print("3. Verify email with PIN")
print("4. Login → QR code appears instantly")
print("5. Phone: Scan QR with camera → Face ID prompt → Device added!")
print("="*60 + "\n")

# Initialize BMAuth
auth = BMAuth(
    app,
    host=host_for_webauthn,
    email_api_key=os.getenv("SENDGRID_API_KEY"),
    from_email="SaMiLMelhem23@gmail.com"
)

# Your regular app routes
@app.get("/")
async def root():
    return {
        "message": "Welcome to BMAuth Test App",
        "endpoints": {
            "register": "/auth/register",
            "login": "/auth/login",
            "verify": "/auth/verify",
            "status": "/auth/status"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
