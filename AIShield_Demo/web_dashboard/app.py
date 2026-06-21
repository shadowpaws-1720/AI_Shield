"""
AIShield Web Dashboard — Flask Backend
========================================
Serves the presentation UI and handles PDF scan requests via REST API.

Routes:
    GET  /           → Dashboard page
    POST /api/scan   → Upload and scan a PDF, returns JSON results

Usage:
    python app.py
    Then open http://localhost:5000 in your browser.
"""

import os
import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
import json
import tempfile
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory

# Add parent directory to import path for the scanner module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aishield_scanner import AIShieldScanner

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

scanner = AIShieldScanner()


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_pdf():
    """
    Accept a PDF upload, scan it for threats, return JSON results.

    Request:  multipart/form-data with field "file" (PDF)
    Response: JSON with verdict, risk_score, findings, etc.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided in request"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not uploaded.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files are supported"}), 400

    # Save to a temp location, scan, then clean up
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, uploaded.filename)

    try:
        uploaded.save(tmp_path)
        result = scanner.scan(tmp_path)
        return jsonify(result.to_dict())
    except FileNotFoundError as exc:
        return jsonify({"error": f"File error: {exc}"}), 400
    except ValueError as exc:
        return jsonify({"error": f"Validation error: {exc}"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500
    finally:
        # Clean up temp files
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        if os.path.exists(tmp_dir):
            os.rmdir(tmp_dir)


if __name__ == "__main__":
    print()
    print("  \U0001F6E1\uFE0F  AIShield Dashboard")
    print("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
    print("  Running at: http://localhost:5000")
    print("  Press Ctrl+C to stop.")
    print()
    app.run(debug=True, host="127.0.0.1", port=5000)
