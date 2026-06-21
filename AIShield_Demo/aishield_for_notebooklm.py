"""
AIShield for NotebookLM — Gateway Script
==========================================
Command-line security gateway that scans PDF documents for hidden
prompt injection attacks before they are uploaded to AI assistants.

Wraps the AIShield scanner with rich terminal output including
color-coded verdicts, threat tables, and risk visualization.

Usage:
    python aishield_for_notebooklm.py <pdf_file>

Examples:
    python aishield_for_notebooklm.py poisoned_resume.pdf
    python aishield_for_notebooklm.py clean_resume.pdf
"""

import sys
import os

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

from aishield_scanner import AIShieldScanner, Severity


# ═══════════════════════════════════════════════════════════════
#  Terminal styling
# ═══════════════════════════════════════════════════════════════

class C:
    """ANSI escape codes for terminal colors."""
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"
    BG_GRN  = "\033[42m"


SEVERITY_STYLE = {
    Severity.CRITICAL: (C.RED,     "\U0001F534"),   # 🔴
    Severity.HIGH:     (C.MAGENTA, "\U0001F7E0"),   # 🟠
    Severity.MEDIUM:   (C.YELLOW,  "\U0001F7E1"),   # 🟡
    Severity.LOW:      (C.CYAN,    "\U0001F535"),   # 🔵
}


# ═══════════════════════════════════════════════════════════════
#  Display functions
# ═══════════════════════════════════════════════════════════════

def print_banner():
    """Print the AIShield startup banner."""
    print(f"""
{C.CYAN}{C.BOLD}
    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
    \u2551           \U0001F6E1\uFE0F  AIShield Scanner v1.0  \U0001F6E1\uFE0F              \u2551
    \u2551    Intelligent Firewall for AI Prompt Injection     \u2551
    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
{C.RESET}""")


def risk_bar(score: int) -> str:
    """Generate a visual risk meter for the terminal."""
    filled = score // 10
    empty = 10 - filled

    if score >= 70:
        color = C.RED
    elif score >= 30:
        color = C.YELLOW
    else:
        color = C.GREEN

    bar = "\u2588" * filled + "\u2591" * empty
    return f"{color}{C.BOLD}{score}/100 {bar}{C.RESET}"


def print_result(result):
    """Print formatted scan results with color-coded output."""

    # ── Verdict banner ──────────────────────────────────────────
    if result.is_blocked:
        print(f"""
{C.BG_RED}{C.WHITE}{C.BOLD}
    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
    \u2551           \U0001F6A8  VERDICT: BLOCKED  \U0001F6A8                \u2551
    \u2551      Prompt injection threats detected!             \u2551
    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
{C.RESET}""")
    else:
        print(f"""
{C.BG_GRN}{C.WHITE}{C.BOLD}
    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
    \u2551            \u2705  VERDICT: ALLOWED  \u2705                 \u2551
    \u2551        No threats detected \u2014 safe to upload        \u2551
    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
{C.RESET}""")

    # ── Scan summary ────────────────────────────────────────────
    print(f"  {C.BOLD}Scan Summary{C.RESET}")
    print(f"  {'\u2500' * 52}")
    print(f"  File:         {C.BOLD}{result.filename}{C.RESET}")
    print(f"  Pages:        {result.total_pages}")
    print(f"  Text Length:  {result.text_length:,} characters")
    print(f"  Scan Time:    {result.scan_time_ms:.1f}ms")
    print(f"  Risk Score:   {risk_bar(result.risk_score)}")

    # ── Threat details ──────────────────────────────────────────
    if result.findings:
        print()
        print(f"  {C.BOLD}Threats Detected ({len(result.findings)}){C.RESET}")
        print(f"  {'\u2500' * 52}")

        for i, finding in enumerate(result.findings, 1):
            color, icon = SEVERITY_STYLE.get(finding.severity, (C.WHITE, "\u26AA"))
            print(f"  {icon} {color}{C.BOLD}[{finding.severity}]{C.RESET} {finding.description}")
            print(f"     {C.DIM}Category: {finding.category}{C.RESET}")
            if finding.page:
                print(f"     {C.DIM}Page:     {finding.page}{C.RESET}")
            evidence_preview = finding.evidence[:80]
            print(f"     {C.DIM}Evidence: \"{evidence_preview}\"{C.RESET}")
            print()
    else:
        print()
        print(f"  {C.GREEN}\u2714 No threats detected. Document is clean.{C.RESET}")

    # ── Final recommendation ────────────────────────────────────
    print(f"  {'\u2500' * 52}")
    if result.is_blocked:
        print(f"  {C.RED}{C.BOLD}\u26D4 DO NOT upload this file to any AI assistant.{C.RESET}")
        print(f"  {C.RED}   Hidden instructions could hijack the AI's behavior")
        print(f"     and exfiltrate sensitive data.{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}\u2713 Safe to upload to NotebookLM or other AI assistants.{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main():
    print_banner()

    if len(sys.argv) < 2:
        print(f"  {C.YELLOW}Usage:{C.RESET} python {os.path.basename(sys.argv[0])} <pdf_file>")
        print()
        print(f"  {C.DIM}Examples:")
        print(f"    python {os.path.basename(sys.argv[0])} poisoned_resume.pdf")
        print(f"    python {os.path.basename(sys.argv[0])} clean_resume.pdf{C.RESET}")
        print()
        sys.exit(1)

    pdf_path = sys.argv[1]

    if not os.path.exists(pdf_path):
        print(f"  {C.RED}{C.BOLD}Error:{C.RESET}{C.RED} File not found \u2014 {pdf_path}{C.RESET}")
        print()
        sys.exit(1)

    if not pdf_path.lower().endswith(".pdf"):
        print(f"  {C.RED}{C.BOLD}Error:{C.RESET}{C.RED} Expected a PDF file \u2014 {pdf_path}{C.RESET}")
        print()
        sys.exit(1)

    print(f"  {C.CYAN}Scanning:{C.RESET} {pdf_path}")
    print(f"  {C.DIM}Running multi-layer threat detection...{C.RESET}")
    print()

    scanner = AIShieldScanner()
    result = scanner.scan(pdf_path)
    print_result(result)

    # Exit code: 1 = blocked (threat), 0 = allowed (clean)
    sys.exit(1 if result.is_blocked else 0)


if __name__ == "__main__":
    main()
