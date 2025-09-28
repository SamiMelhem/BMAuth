"""
BMAuth Command Line Interface.

This module provides CLI commands for managing BMAuth installations,
database setup, and project initialization.
"""

import os
import sys
import asyncio
import click
from pathlib import Path
from typing import Optional

from .core.config import BMAuthConfig
from .core.auth import BMAuth


@click.group()
@click.version_option(version="1.0.0", prog_name="bmauth")
def main():
    """BMAuth - Biometric Authentication for FastAPI applications."""
    pass


@main.command()
@click.option("--project-name", prompt="Project name", help="Name of your FastAPI project")
@click.option("--directory", default=".", help="Directory to create project in")
def init(project_name: str, directory: str):
    """Initialize a new BMAuth project."""
    project_path = Path(directory) / project_name

    if project_path.exists():
        click.echo(f"❌ Directory {project_path} already exists!")
        sys.exit(1)

    try:
        project_path.mkdir(parents=True)
        click.echo(f"📁 Created project directory: {project_path}")

        # Create main application file
        main_py = project_path / "main.py"
        main_py.write_text(get_main_template(project_name))
        click.echo("📄 Created main.py")

        # Create requirements file
        requirements_txt = project_path / "requirements.txt"
        requirements_txt.write_text(get_requirements_template())
        click.echo("📄 Created requirements.txt")

        # Create environment file
        env_file = project_path / ".env"
        env_file.write_text(get_env_template())
        click.echo("📄 Created .env")

        # Create config file
        config_py = project_path / "config.py"
        config_py.write_text(get_config_template())
        click.echo("📄 Created config.py")

        click.echo(f"\n✅ BMAuth project '{project_name}' created successfully!")
        click.echo(f"\nNext steps:")
        click.echo(f"1. cd {project_name}")
        click.echo(f"2. pip install -r requirements.txt")
        click.echo(f"3. bmauth db init")
        click.echo(f"4. uvicorn main:app --reload")

    except Exception as e:
        click.echo(f"❌ Failed to create project: {e}")
        sys.exit(1)


@main.group()
def db():
    """Database management commands."""
    pass


@db.command()
@click.option("--database-url", help="Database URL")
def init(database_url: Optional[str]):
    """Initialize database tables."""
    config = BMAuthConfig()
    if database_url:
        config.database_url = database_url

    async def init_db():
        auth = BMAuth(config=config)
        await auth._initialize_database()
        click.echo("✅ Database initialized successfully!")

    try:
        asyncio.run(init_db())
    except Exception as e:
        click.echo(f"❌ Database initialization failed: {e}")
        sys.exit(1)


@db.command()
@click.option("--database-url", help="Database URL")
def migrate(database_url: Optional[str]):
    """Run database migrations."""
    config = BMAuthConfig()
    if database_url:
        config.database_url = database_url

    click.echo("🔄 Running database migrations...")

    # Here you would typically use Alembic
    # For now, just recreate tables
    async def migrate_db():
        auth = BMAuth(config=config)
        await auth._initialize_database()
        await auth._initialize_partitioning()
        click.echo("✅ Database migrations completed!")

    try:
        asyncio.run(migrate_db())
    except Exception as e:
        click.echo(f"❌ Database migration failed: {e}")
        sys.exit(1)


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def serve(host: str, port: int, reload: bool):
    """Start BMAuth development server."""
    try:
        import uvicorn

        # Look for main.py in current directory
        if not Path("main.py").exists():
            click.echo("❌ No main.py found in current directory!")
            click.echo("💡 Run 'bmauth init <project-name>' to create a new project")
            sys.exit(1)

        click.echo(f"🚀 Starting BMAuth server on {host}:{port}")
        if reload:
            click.echo("🔄 Auto-reload enabled")

        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            reload=reload
        )
    except ImportError:
        click.echo("❌ uvicorn not installed. Install with: pip install uvicorn[standard]")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Server failed to start: {e}")
        sys.exit(1)


@main.command()
def config():
    """Show current BMAuth configuration."""
    try:
        config = BMAuthConfig()

        click.echo("📋 BMAuth Configuration:")
        click.echo(f"Database URL: {config.database_url}")
        click.echo(f"Debug Mode: {config.debug}")
        click.echo(f"Dashboard Enabled: {config.enable_dashboard}")
        click.echo(f"Caching Enabled: {config.enable_caching}")
        click.echo(f"Rate Limiting Enabled: {config.enable_rate_limiting}")
        click.echo(f"WebAuthn RP ID: {config.rp_id}")
        click.echo(f"WebAuthn RP Name: {config.rp_name}")

    except Exception as e:
        click.echo(f"❌ Failed to load configuration: {e}")
        sys.exit(1)


@main.command()
def version():
    """Show BMAuth version information."""
    click.echo("BMAuth v1.0.0")
    click.echo("Production-ready WebAuthn/FIDO2 biometric authentication for FastAPI")


def get_main_template(project_name: str) -> str:
    """Get main.py template."""
    return f'''"""
{project_name} - BMAuth FastAPI Application
"""

from fastapi import FastAPI
from bmauth import BMAuth, BMAuthConfig
from config import get_config

# Create FastAPI app
app = FastAPI(
    title="{project_name}",
    description="FastAPI application with BMAuth biometric authentication",
    version="1.0.0"
)

# Initialize BMAuth
config = get_config()
auth = BMAuth(app, config=config)


@app.get("/")
async def root():
    """Root endpoint."""
    return {{
        "message": "Welcome to {project_name}",
        "bmauth_enabled": True,
        "dashboard": "/bmauth/dashboard" if config.enable_dashboard else None
    }}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {{
        "status": "healthy",
        "bmauth_initialized": auth.is_initialized
    }}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''


def get_requirements_template() -> str:
    """Get requirements.txt template."""
    return '''bmauth>=1.0.0
uvicorn[standard]>=0.24.0
python-dotenv>=1.0.0
'''


def get_env_template() -> str:
    """Get .env template."""
    return '''# BMAuth Configuration
BMAUTH_DATABASE_URL=sqlite+aiosqlite:///./bmauth.db
BMAUTH_SECRET_KEY=change-this-in-production
BMAUTH_DEBUG=true
BMAUTH_ENABLE_DASHBOARD=true
BMAUTH_DASHBOARD_USERNAME=admin
BMAUTH_DASHBOARD_PASSWORD=change-this-password
BMAUTH_RP_ID=localhost
BMAUTH_RP_NAME=My BMAuth App
'''


def get_config_template() -> str:
    """Get config.py template."""
    return '''"""
Configuration for BMAuth application.
"""

import os
from bmauth import BMAuthConfig


def get_config() -> BMAuthConfig:
    """Get BMAuth configuration."""
    return BMAuthConfig(
        # Database
        database_url=os.getenv("BMAUTH_DATABASE_URL", "sqlite+aiosqlite:///./bmauth.db"),

        # Security
        secret_key=os.getenv("BMAUTH_SECRET_KEY", "change-this-in-production"),

        # WebAuthn
        rp_id=os.getenv("BMAUTH_RP_ID", "localhost"),
        rp_name=os.getenv("BMAUTH_RP_NAME", "My BMAuth App"),
        rp_origins=[
            "http://localhost:8000",
            "https://localhost:8000"
        ],

        # Features
        debug=os.getenv("BMAUTH_DEBUG", "false").lower() == "true",
        enable_dashboard=os.getenv("BMAUTH_ENABLE_DASHBOARD", "true").lower() == "true",
        enable_caching=True,
        enable_rate_limiting=True,

        # Dashboard
        dashboard_username=os.getenv("BMAUTH_DASHBOARD_USERNAME", "admin"),
        dashboard_password=os.getenv("BMAUTH_DASHBOARD_PASSWORD", "change-this-password"),
    )
'''


if __name__ == "__main__":
    main()