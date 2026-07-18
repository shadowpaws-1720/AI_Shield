"""
AIShield — Scan Blueprint
===========================
Handles file uploads, scanning, and returning results.
Supports PDF, DOCX, XLSX, HTML, TXT, MD formats.
Saves results to DB when authenticated.

Endpoints:
  POST /api/scan           — Upload and scan file(s)
  POST /api/scan/text      — Scan raw text (Attack Playground)
"""

import os
import sys
import json
import tempfile
from pathlib import Path

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request

# Add parent directory to import path for scanner module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aishield_scanner import AIShieldScanner

from .extensions import db
from .models import User, ScanRecord

scan_bp = Blueprint("scan", __name__, url_prefix="/api")

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".txt", ".md", ".html", ".htm", ".csv"}

_scanner = None

def get_scanner() -> AIShieldScanner:
    global _scanner
    if _scanner is None:
        threshold = int(os.environ.get("BLOCK_THRESHOLD", 30))
        _scanner = AIShieldScanner(block_threshold=threshold)
    return _scanner


def _get_optional_user():
    """Try to get authenticated user; return None if unauthenticated."""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return User.query.get(user_id)
    except Exception:
        pass

    # Try X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return User.query.filter_by(api_key=api_key).first()

    return None


def _save_scan(user: User, result_dict: dict, fmt: str):
    """Persist a scan result to the database and update user stats."""
    from .gamification import check_and_award_badges

    record = ScanRecord(
        user_id           = user.id,
        filename          = result_dict["filename"],
        file_format       = fmt,
        verdict           = result_dict["verdict"],
        risk_score        = result_dict["risk_score"],
        scan_time_ms      = result_dict["scan_time_ms"],
        total_pages       = result_dict.get("total_pages", 0),
        text_length       = result_dict.get("text_length", 0),
        findings_json     = json.dumps(result_dict.get("findings", [])),
        threat_summary_json = json.dumps(result_dict.get("threat_summary", {})),
    )
    db.session.add(record)

    # Update user stats
    user.scan_count  += 1
    user.threat_count += len(result_dict.get("findings", []))
    user.add_format(fmt)
    db.session.commit()

    # Check gamification badges
    check_and_award_badges(user, record)

    return record


@scan_bp.route("/scan", methods=["POST"])
def scan_files():
    """
    Scan one or more uploaded files.
    Accepts multipart/form-data with field 'file' or 'files[]'.
    Returns JSON array of scan results.
    """
    user = _get_optional_user()
    scanner = get_scanner()

    # Accept either 'file' (single) or 'files[]' (multi)
    files = request.files.getlist("files[]") or request.files.getlist("file")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No file(s) provided"}), 400

    results = []
    for uploaded in files:
        if not uploaded or uploaded.filename == "":
            continue

        ext = Path(uploaded.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            results.append({
                "filename": uploaded.filename,
                "error": f"Unsupported format '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            })
            continue

        tmp_dir  = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, uploaded.filename)

        try:
            uploaded.save(tmp_path)
            result = scanner.scan(tmp_path)
            result_dict = result.to_dict()

            # Persist when authenticated
            if user:
                record = _save_scan(user, result_dict, ext.lstrip("."))
                result_dict["scan_id"] = record.id

            results.append(result_dict)

        except Exception as exc:
            results.append({"filename": uploaded.filename, "error": str(exc)})
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.exists(tmp_dir):
                os.rmdir(tmp_dir)

    if len(results) == 1:
        return jsonify(results[0])
    return jsonify({"results": results, "count": len(results)})


@scan_bp.route("/scan/text", methods=["POST"])
def scan_text():
    """
    Scan raw text (used by the Attack Playground tab).
    No file upload needed — just POST JSON with 'text' field.
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    scanner = get_scanner()
    result = scanner.scan_text(text)
    return jsonify(result.to_dict())
