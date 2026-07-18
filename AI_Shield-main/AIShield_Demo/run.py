"""
run.py — AIShield V2 entry point
==================================
Start the AIShield dashboard from the project root:

    python run.py

This avoids any package-import issues.
"""
import os
from web_dashboard.app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_ENV", "development").lower() != "production"
    print()
    print("  [AIShield Dashboard v2.0]")
    print("  ------------------------------")
    print(f"  Running at: http://0.0.0.0:{port}")
    print("  Press Ctrl+C to stop.")
    print()
    app.run(debug=debug, host="0.0.0.0", port=port)

