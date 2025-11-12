# bmauth/dev_tunnel.py
from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
from typing import Optional
from urllib.parse import urlparse


LOCAL_TUNNEL_CMD = ["npx", "localtunnel"]


def _ensure_node_available() -> None:
    """Check that npx is available before attempting to spawn localtunnel."""
    try:
        subprocess.run(
            ["npx", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError(
            "Unable to locate `npx`. Please install Node.js 16+ so BMAuth can launch "
            "LocalTunnel automatically."
        ) from exc


def _pipe_stream(stream, prefix: str = "") -> None:
    for line in iter(stream.readline, ""):
        sys.stdout.write(f"{prefix}{line}")
    stream.close()


def start_dev_tunnel(
    app_import_path: str = "tests.test_app:app",
    port: int = 8000,
    subdomain: Optional[str] = None,
    uvicorn_args: Optional[list[str]] = None,
) -> None:
    """
    Launch the BMAuth test application and expose it through LocalTunnel.

    Args:
        app_import_path: Module path to the ASGI app (default: tests.test_app:app)
        port: Local port uvicorn should bind to
        subdomain: Optional custom subdomain for LocalTunnel (requires availability)
        uvicorn_args: Additional CLI args for uvicorn (list of strings)
    """
    _ensure_node_available()

    lt_cmd = LOCAL_TUNNEL_CMD + ["--port", str(port)]
    if subdomain:
        lt_cmd += ["--subdomain", subdomain]

    lt_proc = subprocess.Popen(
        lt_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    tunnel_url: Optional[str] = None
    assert lt_proc.stdout is not None
    for line in lt_proc.stdout:
        sys.stdout.write(line)
        match = re.search(r"(https://[^\s]+)", line)
        if match:
            tunnel_url = match.group(1)
            break

    if not tunnel_url:
        lt_proc.terminate()
        raise RuntimeError("Could not obtain tunnel URL from localtunnel output.")

    host = urlparse(tunnel_url).netloc  # e.g., xyz.loca.lt
    env = os.environ.copy()
    env["BMAUTH_HOST"] = host

    uvicorn_cmd = [
        "uvicorn",
        app_import_path,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "info",
    ]
    if uvicorn_args:
        uvicorn_cmd += uvicorn_args

    uvicorn_proc = subprocess.Popen(uvicorn_cmd, env=env)

    print("\n" + "=" * 60)
    print("🌐 BMAuth LocalTunnel Dev Server")
    print("=" * 60)
    print(f"Public URL:  {tunnel_url}")
    print(f"Local URL:   http://127.0.0.1:{port}")
    print(f"Host used for WebAuthn RP ID: {host}")
    print("Press Ctrl+C to stop both uvicorn and LocalTunnel.\n")

    # Continue piping LocalTunnel output in background
    threading.Thread(target=_pipe_stream, args=(lt_proc.stdout, "[localtunnel] "), daemon=True).start()

    try:
        uvicorn_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for proc in (uvicorn_proc, lt_proc):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        for proc in (uvicorn_proc, lt_proc):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Launch the BMAuth dev server and expose it via LocalTunnel."
    )
    parser.add_argument(
        "--app",
        default="tests.test_app:app",
        help="ASGI application import path (default: tests.test_app:app)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Local port to bind uvicorn to (default: 8000)",
    )
    parser.add_argument(
        "--subdomain",
        help="Optional custom LocalTunnel subdomain (requires availability).",
    )
    parser.add_argument(
        "--",
        dest="uvicorn_sep",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "uvicorn_args",
        nargs=argparse.REMAINDER,
        help="Additional arguments to forward to uvicorn (prefix with --).",
    )

    args = parser.parse_args(argv)
    extra = args.uvicorn_args
    if extra and extra[0] == "--":
        extra = extra[1:]

    start_dev_tunnel(
        app_import_path=args.app,
        port=args.port,
        subdomain=args.subdomain,
        uvicorn_args=extra or None,
    )