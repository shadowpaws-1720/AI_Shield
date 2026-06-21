# AIShield: Intelligent Firewall Against Zero-Click AI Prompt Injection

> *Protecting AI assistants from hidden commands in documents.*

AIShield scans PDF documents for hidden prompt injection payloads **before** they reach AI models like NotebookLM, ChatGPT, or Copilot — preventing zero-click data exfiltration through invisible instructions.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate test PDFs (poisoned + clean)
python create_poison_pdf.py

# 3. Scan the poisoned PDF
python aishield_for_notebooklm.py poisoned_resume.pdf
#  → 🚨 VERDICT: BLOCKED

# 4. Scan the clean PDF
python aishield_for_notebooklm.py clean_resume.pdf
#  → ✅ VERDICT: ALLOWED
```

## Web Dashboard

```bash
# Launch the presentation dashboard
cd web_dashboard
python app.py
# Open http://localhost:5000 in your browser
```

## Project Structure

```
AIShield_Demo/
├── aishield_scanner.py           # Core detection engine
├── aishield_for_notebooklm.py    # CLI gateway with colored output
├── create_poison_pdf.py          # Generates poisoned + clean test PDFs
├── exfiltration_server.py        # Mock attacker server (demo)
├── requirements.txt              # Python dependencies
├── README.md                     # This file
│
├── web_dashboard/                # Presentation UI
│   ├── app.py                    # Flask backend
│   ├── templates/index.html      # Dashboard page
│   └── static/
│       ├── style.css             # Dark glassmorphism styles
│       └── script.js             # Upload + animation logic
│
├── poisoned_resume.pdf           # Generated — contains hidden attacks
└── clean_resume.pdf              # Generated — clean resume
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
