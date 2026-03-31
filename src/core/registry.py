"""
Obscura47 Bootstrap Registry Server (module version)

Wraps the standalone FastAPI registry for use via `python -m src.main registry`.
"""

from src.utils.config import REGISTRY_HOST, REGISTRY_PORT


def run_registry(host: str | None = None, port: int | None = None):
    """Start the bootstrap registry server using uvicorn."""
    import uvicorn
    # Import the FastAPI app from the standalone registry
    from registry_server import app

    host = host or REGISTRY_HOST
    port = port or REGISTRY_PORT

    print(f"[registry] Obscura47 bootstrap registry (FastAPI) on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_registry()
