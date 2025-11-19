"""
Test FastAPI app with BMAuth integration
"""
from os import getenv
from dotenv import load_dotenv
from uvicorn import run
from fastapi import FastAPI
from bmauth.auth import BMAuth

# Load environment variables from .env file
load_dotenv()

# Create FastAPI app
app = FastAPI(title="BMAuth Test App")

# Configure Supabase storage (defaults to in-memory if omitted)
# getenv() methods are what happens under the hood
database_config = {
    "provider": "supabase",
    "url": getenv("SUPABASE_URL"), # REQUIRED
    "key": getenv("SUPABASE_SERVICE_ROLE_KEY"), # REQUIRED
    "postgres_dsn": getenv("SUPABASE_DB_URL"), # REQUIRED (creates auth tables), Optional after
    "schema": getenv("SUPABASE_SCHEMA"), # Default: "public"
    "table_prefix": getenv("SUPABASE_TABLE_PREFIX"), # Default: "bmauth_"
    "auto_create_tables": True, # Optional: create auth tables automatically
}

host = getenv("BMAUTH_HOST", "localhost") # can specify a custom host

# Initialize BMAuth
auth = BMAuth(
    app,
    database=database_config,
    host=host,
    email_api_key=getenv("SENDGRID_API_KEY"),
    from_email=getenv("SENDGRID_FROM_EMAIL", "noreply@domain.com"),
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
            "status": "/auth/status",
            "debug_storage": "/auth/debug/storage",
        }
    }

if __name__ == "__main__":
    run(app, host=host, port=8000)
