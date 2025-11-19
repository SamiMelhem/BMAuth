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
from os import getenv
from dotenv import load_dotenv
from fastapi import FastAPI
from bmauth import BMAuth

# Load environment variables from a .env file
load_dotenv()

app = FastAPI()

# Optional: configure Supabase storage (defaults to in-memory if omitted)
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
    app=app,
    database=database_config,
    host=host,
    email_api_key="your-sendgrid-api-key",
    from_email="noreply@yourdomain.com"
)

# Initialize BMAuth
auth = BMAuth(
    app,
    database=database_config,
    host=host_for_webauthn,
    email_api_key=os.getenv("SENDGRID_API_KEY"),
    from_email=getenv("SENDGRID_FROM_EMAIL", "noreply@domain.com")
)

# Your app now has biometric authentication endpoints!
```

## Supabase Database Storage

BMAuth ships with an optional Supabase/Postgres storage backend so you can persist biometric data instead of using the default in-memory dictionaries.

### Supabase client overview

Under the hood BMAuth creates a first-class Supabase `Client` via `SupabaseStorage`. When you pass `{"provider": "supabase", "url": "...", "key": "..."}` the storage layer:

- boots a Supabase `Client` scoped to your database/schema
- exposes helpers such as `schema_sql()` and `ensure_tables()` so you can create the four required tables (`users`, `challenges`, `verification_pins`, `device_sessions`)
- persists the full lifecycle for registration (`save_user`, `set_verification_pin`) and biometric verification (`get_challenge`, `set_challenge`, `set_device_session`, etc.)
- surfaces `/auth/debug/storage` so you can inspect what was written to Supabase during development

With this client in place you can:

1. **Create tables automatically** – set `"auto_create_tables": True` and supply `"postgres_dsn"` (or export `SUPABASE_DB_URL`). BMAuth will call `SupabaseStorage.ensure_tables()` on startup, executing the SQL returned by `schema_sql()`.
2. **Register users** – the `/auth/register` route stores the WebAuthn credential payload in the `bmauth_users` table and writes an email verification PIN into `bmauth_verification_pins`.
3. **Verify users** – when a user submits the email PIN the storage backend removes the one-time PIN record, and future sign-ins read/write WebAuthn challenges and device sessions through Supabase.

> Tip: You can call `SupabaseStorage.schema_sql(table_prefix="your_prefix_")` from a Python REPL if you want to review or customise the generated SQL before applying it in Supabase.

3. Configure BMAuth with your Supabase project credentials:
   ```python
   import os
   from bmauth import BMAuth

   database_config = {
       "provider": "supabase",
       "url": os.environ["SUPABASE_URL"],
       "key": os.environ["SUPABASE_SERVICE_ROLE_KEY"],  # requires insert/update/delete privileges
       # Optional:
       # "schema": "auth",         # default: public
       # "table_prefix": "bmauth_",  # default: bmauth_
       # "auto_create_tables": True,
       # "postgres_dsn": os.environ["SUPABASE_DB_URL"],  # required when auto_create_tables=True
   }

   auth = BMAuth(
       app=app,
       database=database_config,
       email_api_key=os.environ["SENDGRID_API_KEY"],
       from_email="noreply@yourdomain.com",
   )
   ```

If you prefer to provide your own storage implementation, pass any object that implements the `StorageBackend` interface through the `database` parameter.

### Auto-creating tables

`SupabaseStorage` can create the required tables automatically when given a Postgres connection string (the same DSN shown in the Supabase dashboard). Set `"auto_create_tables": True` and supply `"postgres_dsn"` (or export `SUPABASE_DB_URL`). BMAuth will run the schema returned by `SupabaseStorage.schema_sql()`. If you omit these values, the debug endpoint and registration flow will tell you which tables still need to be created.

> **Heads up:** some corporate or campus networks block direct access to Supabase database hosts (for example, Texas A&M currently flags them as suspicious). If you see DNS errors like `getaddrinfo failed`, switch to a different network/VPN or use Supabase's HTTP APIs/SQL editor to provision the tables.

For quick diagnostics during development, BMAuth also exposes `/auth/debug/storage`, which returns a snapshot of whatever storage backend is configured (including Supabase table contents or in-memory dictionaries).

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


<!-- ## Local Development & Cross-Device Testing

BMAuth ships with a helper command that spins up the demo FastAPI app and exposes it over HTTPS using [LocalTunnel](https://github.com/localtunnel/localtunnel). This lets a phone or tablet hit the same WebAuthn flow as your laptop without configuring certificates or paid tunnelling services.

### Prerequisites
- Python dev dependencies: `pip install -e .[dev]`
- Node.js 16+ (ships with `npx`)
- Optional (faster startup): `npm install -g localtunnel` -->

<!-- ### Start the tunnelled dev server

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

If you prefer to run your own tunnel or reverse proxy, set `BMAUTH_HOST` before starting your app; the sample `tests/test_app.py` will use that value when constructing QR codes and WebAuthn challenges. -->
