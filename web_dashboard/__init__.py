"""
web_dashboard — AIShield Flask application package.
Import create_app from .app to get the application factory.
"""
from .app import create_app

__all__ = ["create_app"]
