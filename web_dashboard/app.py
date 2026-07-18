"""
AIShield Web Dashboard — Application Factory
=============================================
Creates and configures the Flask application with all blueprints,
extensions, and database setup.

Usage:
    python app.py
    Then open http://localhost:5000
"""

import os
import sys
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template

# Ensure parent directory is on the path for scanner imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def create_app(config: dict = None) -> Flask:
    """Application factory — create, configure, and return the Flask app."""
    app = Flask(__name__)

    # ── Load .env before reading config values ─────────────────
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            load_dotenv(env_path, override=True)
    except ImportError:
        pass

    # ── Core configuration ────────────────────────────────────
    app.config.update(
        SECRET_KEY                = os.environ.get("SECRET_KEY", "dev-secret-CHANGE-in-production"),
        SQLALCHEMY_DATABASE_URI   = os.environ.get("DATABASE_URL", "sqlite:///aishield.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
        JWT_SECRET_KEY            = os.environ.get("JWT_SECRET_KEY", "jwt-secret-CHANGE-in-production"),
        JWT_TOKEN_LOCATION        = ["headers", "query_string"],
        JWT_ACCESS_TOKEN_EXPIRES  = timedelta(hours=24),
        JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30),
        MAX_CONTENT_LENGTH        = int(os.environ.get("MAX_UPLOAD_MB", 32)) * 1024 * 1024,
    )
    
    if config:
        app.config.update(config)

    # Load OAuth keys into config from env (Authlib requires them in app.config)
    app.config.update(
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
        GITHUB_CLIENT_ID=os.environ.get("GITHUB_CLIENT_ID"),
        GITHUB_CLIENT_SECRET=os.environ.get("GITHUB_CLIENT_SECRET")
    )

    # ── Initialize extensions ─────────────────────────────────
    from .extensions import db, jwt, cors, oauth
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})
    oauth.init_app(app)
    
    # Register Google OAuth
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
    
    # Register GitHub OAuth
    oauth.register(
        name='github',
        api_base_url='https://api.github.com/',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        client_kwargs={'scope': 'user:email'}
    )

    # ── Register blueprints ───────────────────────────────────
    from .auth          import auth_bp
    from .scan          import scan_bp
    from .history       import history_bp
    from .analytics     import analytics_bp
    from .gamification  import gamification_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(gamification_bp)

    # ── Main page route ───────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    # ── Health check ──────────────────────────────────────────
    @app.route("/api/health")
    def health():
        return {"status": "ok", "version": "2.0.0"}

    # ── Create DB tables on first run ─────────────────────────
    with app.app_context():
        from . import models  # noqa: F401 — register models
        db.create_all()

    return app


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    # Support running as: python web_dashboard/app.py
    # Make sure we import from the package correctly
    import importlib, sys as _sys
    pkg = Path(__file__).resolve().parent
    if str(pkg.parent) not in _sys.path:
        _sys.path.insert(0, str(pkg.parent))

    # Reload as package
    app_module = importlib.import_module("web_dashboard.app")
    flask_app = app_module.create_app()

    print()
    print("  [AIShield Dashboard v2.0]")
    print("  ------------------------------")
    print("  Running at: http://localhost:5000")
    print("  Press Ctrl+C to stop.")
    print()
    flask_app.run(debug=True, host="127.0.0.1", port=5000)

