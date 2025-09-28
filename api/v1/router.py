"""Main API router for v1 endpoints."""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, webauthn

api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(webauthn.router, prefix="/webauthn", tags=["WebAuthn"])