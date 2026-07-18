"""
AIShield — Analytics Blueprint
================================
Provides aggregate statistics for the analytics dashboard.

Endpoints:
  GET /api/analytics/summary    — High-level stats for current user
  GET /api/analytics/trends     — Scans per day (last 14 days)
  GET /api/analytics/categories — Threat category breakdown
  GET /api/analytics/global     — Platform-wide anonymized stats
"""

from datetime import datetime, timedelta
from collections import defaultdict
import json

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func

from .extensions import db
from .models import ScanRecord, User

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


@analytics_bp.route("/summary", methods=["GET"])
@jwt_required()
def summary():
    """Aggregate stats for the authenticated user."""
    user_id = get_jwt_identity()

    total_scans  = ScanRecord.query.filter_by(user_id=user_id).count()
    blocked      = ScanRecord.query.filter_by(user_id=user_id, verdict="BLOCKED").count()
    allowed      = total_scans - blocked
    blocked_pct  = round(blocked / total_scans * 100, 1) if total_scans else 0

    avg_risk = db.session.query(func.avg(ScanRecord.risk_score))\
                         .filter_by(user_id=user_id).scalar() or 0

    # Most common threat category
    all_findings = []
    for record in ScanRecord.query.filter_by(user_id=user_id).all():
        all_findings.extend(record.get_findings())

    cat_counts: dict = defaultdict(int)
    for f in all_findings:
        cat_counts[f.get("category", "Unknown")] += 1
    top_category = max(cat_counts, key=cat_counts.get) if cat_counts else "None"

    return jsonify({
        "total_scans":   total_scans,
        "blocked":       blocked,
        "allowed":       allowed,
        "blocked_pct":   blocked_pct,
        "avg_risk_score":round(avg_risk, 1),
        "total_threats": len(all_findings),
        "top_category":  top_category,
    })


@analytics_bp.route("/trends", methods=["GET"])
@jwt_required()
def trends():
    """
    Scans per day for the last N days.
    Query param: days (default 14, max 90)
    """
    user_id = get_jwt_identity()
    days    = min(90, max(7, request.args.get("days", 14, type=int)))
    since   = datetime.utcnow() - timedelta(days=days)

    records = ScanRecord.query.filter(
        ScanRecord.user_id == user_id,
        ScanRecord.created_at >= since,
    ).all()

    # Build daily counts
    counts: dict = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
    for r in records:
        day = r.created_at.strftime("%Y-%m-%d")
        counts[day]["total"]   += 1
        counts[day]["blocked"] += 1 if r.verdict == "BLOCKED" else 0
        counts[day]["allowed"] += 1 if r.verdict == "ALLOWED" else 0

    # Fill missing days with zeros
    labels, totals, blockeds, alloweds = [], [], [], []
    for i in range(days - 1, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(day)
        totals.append(counts[day]["total"])
        blockeds.append(counts[day]["blocked"])
        alloweds.append(counts[day]["allowed"])

    return jsonify({
        "labels":  labels,
        "total":   totals,
        "blocked": blockeds,
        "allowed": alloweds,
    })


@analytics_bp.route("/categories", methods=["GET"])
@jwt_required()
def categories():
    """Threat category breakdown for Chart.js donut."""
    user_id = get_jwt_identity()

    all_findings = []
    for record in ScanRecord.query.filter_by(user_id=user_id).all():
        all_findings.extend(record.get_findings())

    cat_counts: dict = defaultdict(int)
    for f in all_findings:
        cat_counts[f.get("category", "Unknown")] += 1

    labels  = list(cat_counts.keys())
    values  = [cat_counts[k] for k in labels]

    return jsonify({"labels": labels, "values": values})


@analytics_bp.route("/global", methods=["GET"])
def global_stats():
    """Platform-wide anonymized statistics (no auth required)."""
    total_scans  = ScanRecord.query.count()
    total_blocked= ScanRecord.query.filter_by(verdict="BLOCKED").count()
    total_users  = User.query.count()

    # Risk distribution buckets: 0-19, 20-39, 40-59, 60-79, 80-100
    buckets = [0, 0, 0, 0, 0]
    for record in ScanRecord.query.with_entities(ScanRecord.risk_score).all():
        score = record.risk_score
        if score < 20:    buckets[0] += 1
        elif score < 40:  buckets[1] += 1
        elif score < 60:  buckets[2] += 1
        elif score < 80:  buckets[3] += 1
        else:             buckets[4] += 1

    return jsonify({
        "total_scans":   total_scans,
        "total_blocked": total_blocked,
        "total_users":   total_users,
        "blocked_pct":   round(total_blocked / total_scans * 100, 1) if total_scans else 0,
        "risk_distribution": {
            "labels": ["0-19", "20-39", "40-59", "60-79", "80-100"],
            "values": buckets,
        },
    })
