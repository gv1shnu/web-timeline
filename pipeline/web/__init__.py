"""Local web dashboard for the recon pipeline (see serve.py)."""

from .app import create_app

__all__ = ["create_app"]
