"""
AIShield Scanner — Core Detection Engine
=========================================
Multi-layer PDF scanner that detects zero-click prompt injection attacks
hidden inside PDF documents before they reach AI models.

Three-layer defense:
  Layer 1 — Text extraction (visible + hidden content)
  Layer 2 — Pattern-based threat detection (regex matching)
  Layer 3 — Structural and heuristic analysis (metadata, anomalies)
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
from pathlib import Path

try:
    from PyPDF2 import PdfReader
except ImportError:
    raise ImportError(
        "PyPDF2 is required but not installed.\n"
        "Install with: pip install PyPDF2>=3.0.0"
    )


# ═══════════════════════════════════════════════════════════════
#  Data Structures
# ═══════════════════════════════════════════════════════════════

class Severity(Enum):
    """Threat severity classification."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


@dataclass
class Finding:
    """Represents a single detected threat within a PDF."""
    category: str
    description: str
    severity: Severity
    evidence: str
    page: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "description": self.description,
            "severity": str(self.severity),
            "evidence": self.evidence[:200],
            "page": self.page,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete PDF scan."""
    filename: str
    verdict: str
    risk_score: int
    scan_time_ms: float
    findings: List[Finding] = field(default_factory=list)
    total_pages: int = 0
    text_length: int = 0
    metadata_scanned: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "BLOCKED"

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "total_pages": self.total_pages,
            "text_length": self.text_length,
            "metadata_scanned": self.metadata_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "threat_summary": {
                "CRITICAL": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "HIGH": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "MEDIUM": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "LOW": sum(1 for f in self.findings if f.severity == Severity.LOW),
            },
        }


# ═══════════════════════════════════════════════════════════════
#  AIShield Scanner
# ═══════════════════════════════════════════════════════════════

class AIShieldScanner:
    """
    Multi-layer PDF scanner for prompt injection detection.

    Usage:
        scanner = AIShieldScanner()
        result = scanner.scan("document.pdf")
        print(result.verdict)   # "BLOCKED" or "ALLOWED"
        print(result.risk_score)  # 0–100
    """

    # ── Layer 2a: Prompt injection keyword patterns ─────────────
    INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            "Prompt override — ignore previous instructions",
            Severity.CRITICAL,
        ),
        (
            r"system\s+override",
            "System override command detected",
            Severity.CRITICAL,
        ),
        (
            r"you\s+are\s+now\s+.{1,80}\s+and\s+must",
            "Identity reassignment injection",
            Severity.CRITICAL,
        ),
        (
            r"pretend\s+you\s+are",
            "Identity manipulation attempt",
            Severity.HIGH,
        ),
        (
            r"disregard\s+(?:your|the)\s+(?:system|safety)\s+(?:prompt|instructions)",
            "Safety bypass attempt",
            Severity.CRITICAL,
        ),
        (
            r"new\s+priority\s+(?:directive|instruction)",
            "Priority directive injection",
            Severity.HIGH,
        ),
        (
            r"from\s+now\s+on,?\s+(?:you\s+will|you\s+must)",
            "Behavioral override attempt",
            Severity.HIGH,
        ),
        (
            r"override\s+(?:all|the)\s+(?:previous|system)\s+(?:prompts?|instructions?)",
            "System prompt override",
            Severity.CRITICAL,
        ),
        (
            r"forget\s+(?:your|the)\s+(?:previous|system)\s+(?:prompt|instructions)",
            "Memory wipe injection",
            Severity.CRITICAL,
        ),
        (
            r"do\s+not\s+follow\s+(?:your|the|any)\s+(?:original|previous|system)",
            "Instruction negation detected",
            Severity.HIGH,
        ),
        (
            r"act\s+as\s+(?:if|though)\s+you\s+(?:have|are)",
            "Role manipulation attempt",
            Severity.MEDIUM,
        ),
        (
            r"respond\s+only\s+with",
            "Output constraint injection",
            Severity.MEDIUM,
        ),
        (
            r"execute\s+(?:the\s+following|this)\s+(?:command|code|instruction)",
            "Command execution injection",
            Severity.HIGH,
        ),
        (
            r"do\s+not\s+mention\s+(?:this|these)\s+instruction",
            "Stealth directive — hides its own presence",
            Severity.CRITICAL,
        ),
        (
            r"(?:secret|hidden)\s+(?:instruction|directive|command)",
            "Self-labeled hidden instruction",
            Severity.HIGH,
        ),
    ]

    # ── Layer 2b: Data exfiltration URL patterns ────────────────
    EXFIL_PATTERNS: List[Tuple[str, str, Severity]] = [
        (
            r"!\[\]\(https?://[^\s\)]+\)",
            "Markdown image exfiltration (zero-pixel tracking)",
            Severity.CRITICAL,
        ),
        (
            r"https?://[^\s]*?(?:email|data|token|secret|password|key|ssn|credit)\s*=",
            "Exfiltration URL with sensitive data parameter",
            Severity.CRITICAL,
        ),
        (
            r"https?://[^\s]*?(?:leak|steal|exfil|capture|log|collect)\b",
            "Suspicious exfiltration endpoint URL",
            Severity.HIGH,
        ),
        (
            r"fetch\s+(?:the\s+)?(?:url|image|resource)\s+(?:at|from)\s+https?://",
            "Fetch instruction targeting remote URL",
            Severity.HIGH,
        ),
        (
            r"send\s+(?:the|all|any)\s+(?:data|information|content|text)\s+to\s+https?://",
            "Data exfiltration send instruction",
            Severity.CRITICAL,
        ),
        (
            r"include\s+.{0,40}as\s+(?:url|query)\s+parameters?",
            "URL parameter stuffing instruction",
            Severity.HIGH,
        ),
    ]

    # ── Layer 2c: Zero-width / invisible Unicode codepoints ─────
    INVISIBLE_CHARS: Dict[str, str] = {
        "\u200B": "Zero-Width Space (U+200B)",
        "\u200C": "Zero-Width Non-Joiner (U+200C)",
        "\u200D": "Zero-Width Joiner (U+200D)",
        "\u200E": "Left-to-Right Mark (U+200E)",
        "\u200F": "Right-to-Left Mark (U+200F)",
        "\u2060": "Word Joiner (U+2060)",
        "\u2061": "Function Application (U+2061)",
        "\u2062": "Invisible Times (U+2062)",
        "\u2063": "Invisible Separator (U+2063)",
        "\u2064": "Invisible Plus (U+2064)",
        "\uFEFF": "Zero-Width No-Break Space / BOM (U+FEFF)",
        "\u00AD": "Soft Hyphen (U+00AD)",
        "\u034F": "Combining Grapheme Joiner (U+034F)",
        "\u061C": "Arabic Letter Mark (U+061C)",
        "\u180E": "Mongolian Vowel Separator (U+180E)",
    }

    # ── Layer 3a: Suspicious metadata field keywords ────────────
    METADATA_KEYWORDS = [
        "ignore", "override", "inject", "instruction", "prompt",
        "execute", "fetch", "disregard", "forget", "pretend",
        "exfil", "http://", "https://", "system",
    ]

    # ── Scoring ─────────────────────────────────────────────────
    SEVERITY_WEIGHTS = {
        Severity.LOW: 5,
        Severity.MEDIUM: 15,
        Severity.HIGH: 30,
        Severity.CRITICAL: 50,
    }

    DEFAULT_BLOCK_THRESHOLD = 30

    # ────────────────────────────────────────────────────────────

    def __init__(self, block_threshold: int = DEFAULT_BLOCK_THRESHOLD):
        self.block_threshold = block_threshold

        # Pre-compile all regex patterns for performance
        self._re_injection = [
            (re.compile(pat, re.IGNORECASE), desc, sev)
            for pat, desc, sev in self.INJECTION_PATTERNS
        ]
        self._re_exfil = [
            (re.compile(pat, re.IGNORECASE), desc, sev)
            for pat, desc, sev in self.EXFIL_PATTERNS
        ]

    # ── Public API ──────────────────────────────────────────────

    def scan(self, pdf_path: str) -> ScanResult:
        """
        Scan a PDF file for prompt injection threats.

        Args:
            pdf_path: Path to the PDF file to scan.

        Returns:
            ScanResult with verdict ("BLOCKED" / "ALLOWED"),
            risk score (0–100), and a list of findings.
        """
        t_start = time.perf_counter()
        path = Path(pdf_path)
        findings: List[Finding] = []

        if not path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        if path.suffix.lower() != ".pdf":
            raise ValueError(f"Expected a .pdf file, got: {path.suffix}")

        reader = PdfReader(str(path))
        total_pages = len(reader.pages)

        # ── LAYER 1: Text extraction ───────────────────────────
        full_text = ""
        page_texts: Dict[int, str] = {}
        for idx, page in enumerate(reader.pages):
            extracted = page.extract_text() or ""
            page_texts[idx + 1] = extracted
            full_text += extracted + "\n"

        # ── LAYER 2: Pattern-based detection ───────────────────
        findings.extend(self._scan_injection_patterns(full_text, page_texts))
        findings.extend(self._scan_exfil_patterns(full_text, page_texts))
        findings.extend(self._scan_invisible_chars(full_text))

        # ── LAYER 3: Structural / heuristic analysis ───────────
        findings.extend(self._scan_metadata(reader))
        findings.extend(self._scan_text_anomalies(page_texts))

        # ── Score & verdict ────────────────────────────────────
        risk_score = self._calculate_risk(findings)
        verdict = "BLOCKED" if risk_score >= self.block_threshold else "ALLOWED"

        elapsed_ms = (time.perf_counter() - t_start) * 1000

        return ScanResult(
            filename=path.name,
            verdict=verdict,
            risk_score=min(risk_score, 100),
            scan_time_ms=elapsed_ms,
            findings=findings,
            total_pages=total_pages,
            text_length=len(full_text),
            metadata_scanned=True,
        )

    # ── Internal scanning methods ──────────────────────────────

    def _scan_injection_patterns(
        self, text: str, page_texts: Dict[int, str]
    ) -> List[Finding]:
        """Layer 2a — scan for prompt injection keyword patterns."""
        results = []
        for regex, description, severity in self._re_injection:
            for match in regex.finditer(text):
                page = self._locate_page(match.start(), page_texts)
                results.append(Finding(
                    category="Prompt Injection",
                    description=description,
                    severity=severity,
                    evidence=match.group(0),
                    page=page,
                ))
        return results

    def _scan_exfil_patterns(
        self, text: str, page_texts: Dict[int, str]
    ) -> List[Finding]:
        """Layer 2b — scan for data exfiltration URL patterns."""
        results = []
        for regex, description, severity in self._re_exfil:
            for match in regex.finditer(text):
                page = self._locate_page(match.start(), page_texts)
                results.append(Finding(
                    category="Data Exfiltration",
                    description=description,
                    severity=severity,
                    evidence=match.group(0),
                    page=page,
                ))
        return results

    def _scan_invisible_chars(self, text: str) -> List[Finding]:
        """Layer 2c — detect zero-width and invisible Unicode characters."""
        results = []
        detected: Dict[str, int] = {}

        for char, name in self.INVISIBLE_CHARS.items():
            count = text.count(char)
            if count > 0:
                detected[name] = count

        if detected:
            total = sum(detected.values())
            detail = "; ".join(f"{n}: {c}" for n, c in detected.items())
            severity = Severity.HIGH if total > 10 else Severity.MEDIUM
            if total > 50:
                severity = Severity.CRITICAL

            results.append(Finding(
                category="Hidden Characters",
                description=f"Detected {total} invisible Unicode character(s) — "
                            f"possible steganographic payload",
                severity=severity,
                evidence=detail,
            ))
        return results

    def _scan_metadata(self, reader: PdfReader) -> List[Finding]:
        """Layer 3a — inspect PDF metadata fields for injection payloads."""
        results = []
        meta = reader.metadata
        if not meta:
            return results

        field_map = {
            "Title": getattr(meta, "title", None),
            "Author": getattr(meta, "author", None),
            "Subject": getattr(meta, "subject", None),
            "Creator": getattr(meta, "creator", None),
            "Producer": getattr(meta, "producer", None),
        }

        for field_name, value in field_map.items():
            if not value:
                continue
            value_lower = value.lower()

            # Check against full injection patterns first
            for regex, desc, sev in self._re_injection:
                if regex.search(value):
                    results.append(Finding(
                        category="Metadata Injection",
                        description=f"Injection payload found in PDF '{field_name}' field",
                        severity=sev,
                        evidence=f"{field_name}: {value[:150]}",
                    ))
                    break
            else:
                # Fallback: flag suspicious keywords in metadata
                for keyword in self.METADATA_KEYWORDS:
                    if keyword in value_lower:
                        results.append(Finding(
                            category="Suspicious Metadata",
                            description=f"Keyword '{keyword}' found in PDF '{field_name}' field",
                            severity=Severity.LOW,
                            evidence=f"{field_name}: {value[:150]}",
                        ))
                        break

        return results

    def _scan_text_anomalies(self, page_texts: Dict[int, str]) -> List[Finding]:
        """Layer 3b — detect anomalous text patterns suggesting hidden content."""
        results = []
        for page_num, text in page_texts.items():
            if not text:
                continue

            lines = text.split("\n")
            for line in lines:
                stripped = line.strip()
                # Flag extremely long lines lacking normal punctuation
                if len(stripped) > 500 and not any(c in stripped for c in ".!?,;:"):
                    results.append(Finding(
                        category="Text Anomaly",
                        description="Unusually long unpunctuated text block — "
                                    "potential hidden instruction payload",
                        severity=Severity.MEDIUM,
                        evidence=stripped[:120] + "...",
                        page=page_num,
                    ))
        return results

    # ── Utilities ──────────────────────────────────────────────

    def _locate_page(
        self, char_offset: int, page_texts: Dict[int, str]
    ) -> Optional[int]:
        """Map a character offset in the concatenated text back to a page number."""
        running = 0
        for page_num in sorted(page_texts.keys()):
            page_len = len(page_texts[page_num]) + 1   # +1 for the "\n" separator
            if running + page_len > char_offset:
                return page_num
            running += page_len
        return None

    def _calculate_risk(self, findings: List[Finding]) -> int:
        """Compute a composite risk score (0–100) from all findings."""
        if not findings:
            return 0
        raw = sum(self.SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        return min(raw, 100)
