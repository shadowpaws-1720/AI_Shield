"""
AIShield — Gamification Blueprint
====================================
Badge awards, leaderboard, and user achievement tracking.

Endpoints:
  GET /api/badges/me       — Current user's earned badges
  GET /api/badges/all      — All available badge definitions
  GET /api/leaderboard     — Top 10 users by scan count (opt-in, anonymized)
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from .extensions import db
from .models import User, UserBadge, ScanRecord, BADGE_DEFINITIONS

gamification_bp = Blueprint("gamification", __name__)


# ─────────────────────────────────────────────────────────────
#  Badge award logic (called from scan.py after each scan)
# ─────────────────────────────────────────────────────────────

def maybe_award_badge(user: User, badge_key: str) -> bool:
    """Award a badge if not already earned. Returns True if newly awarded."""
    if not UserBadge.query.filter_by(user_id=user.id, badge_key=badge_key).first():
        badge = UserBadge(user_id=user.id, badge_key=badge_key)
        db.session.add(badge)
        db.session.commit()
        return True
    return False


def check_and_award_badges(user: User, record: ScanRecord):
    """
    Evaluate and award all applicable badges after a scan.
    Called from scan.py immediately after saving a ScanRecord.
    """
    newly_awarded = []

    # First scan
    if user.scan_count >= 1:
        if maybe_award_badge(user, "first_scan"):
            newly_awarded.append("first_scan")

    # Security analyst — 50 scans
    if user.scan_count >= 50:
        if maybe_award_badge(user, "security_analyst"):
            newly_awarded.append("security_analyst")

    # Veteran — 200 scans
    if user.scan_count >= 200:
        if maybe_award_badge(user, "veteran"):
            newly_awarded.append("veteran")

    # Threat hunter — cumulative 10 threats found
    if user.threat_count >= 10:
        if maybe_award_badge(user, "threat_hunter"):
            newly_awarded.append("threat_hunter")

    # Eagle eye — first CRITICAL finding
    findings = record.get_findings()
    if any(f.get("severity") == "CRITICAL" for f in findings):
        if maybe_award_badge(user, "eagle_eye"):
            newly_awarded.append("eagle_eye")

    # Format explorer — 3+ different formats
    formats_used = [f.strip() for f in user.formats_used.split(",") if f.strip()]
    if len(set(formats_used)) >= 3:
        if maybe_award_badge(user, "format_explorer"):
            newly_awarded.append("format_explorer")

    return newly_awarded


# ─────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────

@gamification_bp.route("/api/badges/me", methods=["GET"])
@jwt_required()
def my_badges():
    """Return all badges the current user has earned."""
    user_id = get_jwt_identity()
    badges  = UserBadge.query.filter_by(user_id=user_id)\
                             .order_by(UserBadge.earned_at.asc()).all()
    return jsonify({
        "earned":    [b.to_dict() for b in badges],
        "all_badges":[{
            "key":         k,
            "name":        v["name"],
            "icon":        v["icon"],
            "description": v["description"],
            "earned":      any(b.badge_key == k for b in badges),
        } for k, v in BADGE_DEFINITIONS.items()],
    })


@gamification_bp.route("/api/badges/all", methods=["GET"])
def all_badges():
    """Return all badge definitions (no auth required)."""
    return jsonify([
        {"key": k, "name": v["name"], "icon": v["icon"], "description": v["description"]}
        for k, v in BADGE_DEFINITIONS.items()
    ])


@gamification_bp.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    """
    Top 10 users by scan count (anonymized — shows only email prefix + *** suffix).
    """
    top_users = User.query.order_by(User.scan_count.desc()).limit(10).all()

    def anonymize(email: str) -> str:
        name, domain = email.split("@", 1)
        return name[:3] + "***@" + domain

    board = []
    for rank, u in enumerate(top_users, start=1):
        board.append({
            "rank":         rank,
            "email_masked": anonymize(u.email),
            "scan_count":   u.scan_count,
            "threat_count": u.threat_count,
            "badge_count":  UserBadge.query.filter_by(user_id=u.id).count(),
        })

    return jsonify({"leaderboard": board})
