"""
AIShield — SQLAlchemy Models
==============================
Defines User, ScanRecord, UserBadge data models.
"""

import json
import uuid
from datetime import datetime
from .extensions import db

# ─────────────────────────────────────────────────────────────
#  Badge Definitions (static metadata)
# ─────────────────────────────────────────────────────────────

BADGE_DEFINITIONS = {
    "first_scan":       {"name": "First Scan",        "icon": "🔍", "description": "Complete your first document scan"},
    "threat_hunter":    {"name": "Threat Hunter",     "icon": "🎯", "description": "Catch 10 total threats across all scans"},
    "security_analyst": {"name": "Security Analyst",  "icon": "🛡️", "description": "Complete 50 scans"},
    "veteran":          {"name": "Veteran",           "icon": "⚔️",  "description": "Complete 200 scans"},
    "eagle_eye":        {"name": "Eagle Eye",         "icon": "🦅", "description": "Find your first CRITICAL threat"},
    "clean_slate":      {"name": "Clean Slate",       "icon": "✨", "description": "Scan 5 consecutive clean documents"},
    "format_explorer":  {"name": "Format Explorer",   "icon": "📂", "description": "Scan 3 different file formats"},
    "api_master":       {"name": "API Master",        "icon": "🔑", "description": "Generate your first API key"},
}


# ─────────────────────────────────────────────────────────────
#  User Model
# ─────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"

    id           = db.Column(db.Integer, primary_key=True)
    email        = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash= db.Column(db.String(255), nullable=False)
    role         = db.Column(db.String(20), default="analyst")   # admin | analyst | viewer
    api_key      = db.Column(db.String(80), unique=True, nullable=True, index=True)
    scan_count   = db.Column(db.Integer, default=0)
    threat_count = db.Column(db.Integer, default=0)  # cumulative threats found
    formats_used = db.Column(db.String(255), default="")  # comma-separated
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    scans  = db.relationship("ScanRecord", backref="user", lazy="dynamic",
                             cascade="all, delete-orphan")
    badges = db.relationship("UserBadge",  backref="user", lazy="dynamic",
                             cascade="all, delete-orphan")

    def generate_api_key(self) -> str:
        self.api_key = f"ask_{uuid.uuid4().hex}"
        return self.api_key

    def revoke_api_key(self):
        self.api_key = None

    def add_format(self, fmt: str):
        """Track unique file formats this user has scanned."""
        used = set(f.strip() for f in self.formats_used.split(",") if f.strip())
        used.add(fmt.lower())
        self.formats_used = ",".join(used)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "email":       self.email,
            "role":        self.role,
            "has_api_key": bool(self.api_key),
            "scan_count":  self.scan_count,
            "threat_count":self.threat_count,
            "created_at":  self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────
#  ScanRecord Model
# ─────────────────────────────────────────────────────────────

class ScanRecord(db.Model):
    __tablename__ = "scan_records"

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    filename         = db.Column(db.String(255), nullable=False)
    file_format      = db.Column(db.String(20), default="pdf")
    verdict          = db.Column(db.String(10), nullable=False)   # BLOCKED | ALLOWED
    risk_score       = db.Column(db.Integer, default=0)
    scan_time_ms     = db.Column(db.Float, default=0.0)
    total_pages      = db.Column(db.Integer, default=0)
    text_length      = db.Column(db.Integer, default=0)
    findings_json    = db.Column(db.Text, default="[]")
    threat_summary_json = db.Column(db.Text, default="{}")
    created_at       = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def get_findings(self) -> list:
        return json.loads(self.findings_json)

    def get_threat_summary(self) -> dict:
        return json.loads(self.threat_summary_json)

    def threat_count(self) -> int:
        return len(self.get_findings())

    def to_dict(self, include_findings: bool = True) -> dict:
        d = {
            "id":             self.id,
            "filename":       self.filename,
            "file_format":    self.file_format,
            "verdict":        self.verdict,
            "risk_score":     self.risk_score,
            "scan_time_ms":   round(self.scan_time_ms, 2),
            "total_pages":    self.total_pages,
            "text_length":    self.text_length,
            "threat_count":   len(self.get_findings()),
            "threat_summary": self.get_threat_summary(),
            "created_at":     self.created_at.isoformat(),
        }
        if include_findings:
            d["findings"] = self.get_findings()
        return d


# ─────────────────────────────────────────────────────────────
#  UserBadge Model
# ─────────────────────────────────────────────────────────────

class UserBadge(db.Model):
    __tablename__ = "user_badges"

    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    badge_key = db.Column(db.String(50), nullable=False)
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("user_id", "badge_key", name="uq_user_badge"),)

    def to_dict(self) -> dict:
        defn = BADGE_DEFINITIONS.get(self.badge_key, {})
        return {
            "key":         self.badge_key,
            "name":        defn.get("name", self.badge_key),
            "icon":        defn.get("icon", "🏅"),
            "description": defn.get("description", ""),
            "earned_at":   self.earned_at.isoformat(),
        }
