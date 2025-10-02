"""
Test FastAPI app with BMAuth integration
"""
from fastapi import FastAPI
from bmauth.auth import BMAuth
import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Create FastAPI app
app = FastAPI(title="BMAuth Test App")

auth = BMAuth(
    app,
    email_api_key=os.getenv("SENDGRID_API_KEY"),
    from_email="SaMiLMelhem23@gmail.com"
)

# Your regular app routes
@app.get("/")
async def root():
    return {"message": "Welcome to BMAuth Test App"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)