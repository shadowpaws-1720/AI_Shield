"""
AIShield — Authentication Blueprint
=====================================
Handles user registration, login, JWT token management, and API key generation.

Endpoints:
  POST /api/auth/register   — Create new account
  POST /api/auth/login      — Authenticate and receive JWTs
  POST /api/auth/refresh    — Refresh access token
  GET  /api/auth/me         — Current user profile
  POST /api/auth/apikey     — Generate/regenerate personal API key
  DELETE /api/auth/apikey   — Revoke API key
"""

import bcrypt
from flask import Blueprint, request, jsonify, url_for, redirect
from urllib.parse import urlencode
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity,
)
from .extensions import db, oauth
from .models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email address"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(
        email=email,
        password_hash=_hash_password(password),
        role="analyst",
    )
    db.session.add(user)
    db.session.commit()

    access  = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))
    return jsonify({
        "message":       "Account created successfully",
        "access_token":  access,
        "refresh_token": refresh,
        "user":          user.to_dict(),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate and return JWT tokens."""
    data = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not _check_password(password, user.password_hash):
        return jsonify({"error": "Invalid email or password"}), 401

    access  = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))
    return jsonify({
        "access_token":  access,
        "refresh_token": refresh,
        "user":          user.to_dict(),
    })


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Exchange a refresh token for a new access token."""
    user_id = get_jwt_identity()
    access  = create_access_token(identity=str(user_id))
    return jsonify({"access_token": access})


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """Return the current authenticated user's profile."""
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    return jsonify({"user": user.to_dict()})


@auth_bp.route("/apikey", methods=["POST"])
@jwt_required()
def generate_apikey():
    """Generate (or regenerate) the user's personal API key."""
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    key = user.generate_api_key()
    db.session.commit()

    # Award badge if first time generating
    from .gamification import maybe_award_badge
    maybe_award_badge(user, "api_master")

    return jsonify({
        "api_key": key,
        "message": "Keep this key secret — it grants full access to your account.",
    })


@auth_bp.route("/apikey", methods=["DELETE"])
@jwt_required()
def revoke_apikey():
    """Revoke the user's API key."""
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    user.revoke_api_key()
    db.session.commit()
    return jsonify({"message": "API key revoked"})


@auth_bp.route("/login/<provider>", methods=["GET"])
def oauth_login(provider):
    """Redirect to OAuth provider."""
    client = oauth.create_client(provider)
    if not client:
        return jsonify({"error": f"Provider {provider} not supported"}), 404
    
    redirect_uri = url_for("auth.oauth_callback", provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@auth_bp.route("/callback/<provider>", methods=["GET"])
def oauth_callback(provider):
    """Handle OAuth callback and issue JWT."""
    client = oauth.create_client(provider)
    if not client:
        return jsonify({"error": f"Provider {provider} not supported"}), 404
    
    try:
        token = client.authorize_access_token()
    except Exception as e:
        return redirect("/?error=" + urlencode({"error": "OAuth Authorization Failed"}))

    email = None
    
    if provider == "google":
        user_info = token.get("userinfo")
        if user_info:
            email = user_info.get("email")
    elif provider == "github":
        resp = client.get("user/emails")
        if resp.ok:
            emails = resp.json()
            primary = next((e for e in emails if e.get("primary")), None)
            if primary:
                email = primary.get("email")
                
    if not email:
        return redirect("/?error=" + urlencode({"error": "Failed to get email from provider"}))
        
    email = email.lower()
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Create user without password
        user = User(
            email=email,
            password_hash="OAUTH",
            role="analyst",
        )
        db.session.add(user)
        db.session.commit()
        
    access = create_access_token(identity=str(user.id))
    
    # Redirect back to frontend with token in hash fragment
    return redirect(f"/#token={access}")
