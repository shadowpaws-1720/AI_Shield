"""
AIShield — History Blueprint
==============================
Provides paginated access to a user's scan history.

Endpoints:
  GET    /api/history              — Paginated scan list (search, filter)
  GET    /api/history/<id>         — Full scan detail
  DELETE /api/history/<id>         — Delete a scan record
  GET    /api/history/<id>/export  — Download scan as JSON
"""

from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
import json

from .extensions import db
from .models import User, ScanRecord

history_bp = Blueprint("history", __name__, url_prefix="/api/history")


@history_bp.route("", methods=["GET"])
@jwt_required()
def list_history():
    """
    Return paginated scan history for the authenticated user.
    Query params: page (default 1), per_page (default 15, max 50),
                  q (filename search), verdict (BLOCKED|ALLOWED), format
    """
    user_id  = get_jwt_identity()
    page     = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 15, type=int)))
    q        = request.args.get("q", "").strip()
    verdict  = request.args.get("verdict", "").upper()
    fmt      = request.args.get("format", "").lower()

    query = ScanRecord.query.filter_by(user_id=user_id)

    if q:
        query = query.filter(ScanRecord.filename.ilike(f"%{q}%"))
    if verdict in ("BLOCKED", "ALLOWED"):
        query = query.filter_by(verdict=verdict)
    if fmt:
        query = query.filter_by(file_format=fmt)

    query = query.order_by(ScanRecord.created_at.desc())
    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "scans":      [r.to_dict(include_findings=False) for r in paginated.items],
        "total":      paginated.total,
        "page":       page,
        "per_page":   per_page,
        "pages":      paginated.pages,
        "has_next":   paginated.has_next,
        "has_prev":   paginated.has_prev,
    })


@history_bp.route("/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    """Return full detail of a single scan record."""
    user_id = get_jwt_identity()
    record  = ScanRecord.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    return jsonify(record.to_dict(include_findings=True))


@history_bp.route("/<int:scan_id>", methods=["DELETE"])
@jwt_required()
def delete_scan(scan_id):
    """Delete a scan record from the user's history."""
    user_id = get_jwt_identity()
    record  = ScanRecord.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    db.session.delete(record)
    db.session.commit()
    return jsonify({"message": "Scan record deleted"})


@history_bp.route("/<int:scan_id>/export", methods=["GET"])
@jwt_required()
def export_scan(scan_id):
    """Download a scan result as a formatted JSON file."""
    user_id = get_jwt_identity()
    record  = ScanRecord.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    payload = json.dumps(record.to_dict(include_findings=True), indent=2)
    filename = f"aishield_scan_{scan_id}_{record.filename}.json"
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
