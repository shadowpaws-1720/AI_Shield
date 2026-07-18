# AIShield: Intelligent Firewall Against Zero-Click AI Prompt Injection

> *Protecting AI assistants from hidden commands in documents.*

AIShield scans PDF documents for hidden prompt injection payloads **before** they reach AI models like NotebookLM, ChatGPT, or Copilot — preventing zero-click data exfiltration through invisible instructions.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment variables
# Copy .env.example to .env and configure keys
copy .env.example .env

# 3. Launch the web dashboard from the project root
python run.py
# Open http://localhost:5000 in your browser
```

## Project Structure

```
AIShield_Demo/
├── aishield_scanner.py           # Core detection engine
├── run.py                        # Server runner entry point
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment configuration template
├── .gitignore                    # Files ignored by git
├── README.md                     # This file
│
└── web_dashboard/                # Presentation UI & Dashboard
    ├── app.py                    # Flask backend application factory
    ├── models.py                 # DB models (User, ScanRecord, etc.)
    ├── extensions.py             # Flask extension initializations
    ├── auth.py                   # User registration, login & API keys
    ├── scan.py                   # Scanning endpoint hooks
    ├── history.py                # Scan history logs endpoints
    ├── analytics.py              # Visual statistics & trend metrics
    ├── gamification.py           # Achievement badges & leaderboard
    │
    ├── templates/
    │   └── index.html            # Main UI single-page dashboard HTML
    └── static/
        ├── style.css             # Multi-themed glassmorphic stylesheet
        └── script.js             # Client SPA routing & upload AJAX handler
```

## Detection Capabilities

| Attack Vector       | Detection Method    | Severity  |
|---------------------|--------------------:|:---------:|
| Prompt injection    | Regex patterns      | CRITICAL  |
| Exfiltration URLs   | URL pattern matching| CRITICAL  |
| Zero-width Unicode  | Character analysis  | HIGH      |
| Metadata injection  | Field inspection    | HIGH      |
| Hidden text blocks  | Heuristic analysis  | MEDIUM    |

## License

Educational demonstration project.
