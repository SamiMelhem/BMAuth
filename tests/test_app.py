"""
Test FastAPI app with BMAuth integration
"""
from fastapi import FastAPI
from bmauth.auth import BMAuth
import uvicorn

# Create FastAPI app
app = FastAPI(title="BMAuth Test App")

# Initialize BMAuth
auth = BMAuth(app)

# Your regular app routes
@app.get("/")
async def root():
    return {"message": "Welcome to BMAuth Test App"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)