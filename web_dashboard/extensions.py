"""
AIShield Web Dashboard — Flask Extensions
==========================================
Shared extension instances to avoid circular imports.
Initialize with init_app() in the application factory.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth

db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()
oauth = OAuth()
