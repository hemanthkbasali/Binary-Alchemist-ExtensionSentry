from __future__ import annotations

import re
from typing import Iterable

from .file_handler import ExtensionFile
from .utils import extract_urls, finding, safe_decode, shannon_entropy, unique_preserve


LEGIT_EXTENSION_HINTS = [
    "adblock",
    "filterlist",
    "blockelement",
    "declarativenetrequest",
    "google docs",
    "offline",
    "drive",
    "subscription",
    "whitelist",
    "allowlist",
]


PATTERNS = [
    (
        "JS_EVAL",
        "critical",
        "JavaScript",
        r"\beval\s*\(",
        "Dynamic eval execution detected",
        "Eval can execute remotely influenced strings as privileged extension code.",
        "Remove eval and replace dynamic execution with static dispatch tables.",
    ),
    (
        "JS_FUNCTION_CONSTRUCTOR",
        "high",
        "JavaScript",
        r"\bnew\s+Function\s*\(",
        "Function constructor dynamic execution detected",
        "The Function constructor can turn attacker-controlled strings into code.",
        "Replace Function constructors with explicit functions and validated inputs.",
    ),
    (
        "JS_REMOTE_SCRIPT_INJECTION",
        "high",
        "JavaScript",
        r"createElement\s*\(\s*['\"]script['\"]\s*\).{0,120}\.src\s*=\s*['\"]https?://",
        "Remote script injection behavior detected",
        "The extension appears capable of injecting script elements sourced from remote locations.",
        "Bundle scripts locally and block remote script construction.",
    ),
    (
        "JS_CHROME_TABS_ACCESS",
        "low",
        "Chrome API",
        r"\bchrome\.tabs\.",
        "Chrome tabs API access observed",
        "Code paths interact with browser tab metadata or execution surfaces.",
        "Review tab access paths and restrict them to user-initiated workflows.",
    ),
    (
        "JS_COOKIE_ACCESS",
        "medium",
        "Chrome API",
        r"\bchrome\.cookies\.",
        "Cookie API access observed",
        "Extension code can interact with browser cookies.",
        "Remove cookie access unless needed for a documented security use case.",
    ),
    (
        "JS_KEYLOGGER",
        "high",
        "Credential Risk",
        r"(addEventListener\s*\(\s*['\"]key(?:down|press|up)['\"]|onkey(?:down|press|up)).{0,80}(password|passwd|login|credential|secret)",
        "Credential-adjacent keystroke capture",
        "Keyboard handlers appear near credential-sensitive identifiers.",
        "Confirm no credential telemetry is collected and isolate sensitive inputs.",
    ),
    (
        "JS_STORAGE_SECRET",
        "medium",
        "Credential Risk",
        r"(localStorage|sessionStorage|chrome\.storage).{0,100}(token|secret|password|api[_-]?key|auth)",
        "Sensitive token storage pattern",
        "Credential-like data appears to be stored in browser-accessible storage.",
        "Move secrets to server-side storage or encrypted short-lived tokens.",
    ),
    (
        "JS_DANGEROUS_DOM_SINK",
        "low",
        "DOM",
        r"(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*[=.(]",
        "Dynamic HTML DOM sink usage",
        "HTML-writing sinks can become XSS vectors when paired with untrusted input.",
        "Use safe DOM APIs, templates, and strict sanitization.",
    ),
]

BASE64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{160,}={0,2})['\"]")
HEX_BLOB_RE = re.compile(r"['\"]([a-fA-F0-9]{240,})['\"]")


def legitimacy_modifier(text: str) -> float:
    lower = text.lower()
    hits = sum(1 for hint in LEGIT_EXTENSION_HINTS if hint in lower)
    if hits >= 3:
        return 0.40
    if hits >= 1:
        return 0.62
    return 1.0


def analyze_javascript(js_files: Iterable[ExtensionFile]) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    seen_rule_ids = set()
    total_bytes = 0
    total_lines = 0
    urls: list[str] = []
    scanned_files = 0
    largest_file = {"path": "", "size": 0}

    for js_file in js_files:
        scanned_files += 1
        total_bytes += js_file.size
        if js_file.size > largest_file["size"]:
            largest_file = {"path": js_file.path, "size": js_file.size}

        try:
            text = safe_decode(js_file.absolute_path.read_bytes(), limit=5 * 1024 * 1024)
        except OSError as exc:
            findings.append(
                finding(
                    rule_id="JS_READ_ERROR",
                    severity="low",
                    category="File Handling",
                    title="JavaScript file could not be read",
                    description=str(exc),
                    recommendation="Inspect the file manually or re-upload a clean archive.",
                    evidence={"path": js_file.path},
                    confidence=0.4,
                )
            )
            continue

        total_lines += text.count("\n") + 1
        urls.extend(extract_urls(text))
        compact_text = re.sub(r"\s+", " ", text)
        adjust = legitimacy_modifier(compact_text)

        for rule_id, severity, category, pattern, title, description, recommendation in PATTERNS:
            match = re.search(pattern, compact_text, flags=re.IGNORECASE | re.DOTALL)
            if match and rule_id not in seen_rule_ids:
                sev = severity
                conf = 0.82 * adjust

                if adjust < 0.8 and severity == "critical":
                    sev = "high"
                elif adjust < 0.8 and severity == "high":
                    sev = "medium"

                findings.append(
                    finding(
                        rule_id=rule_id,
                        severity=sev,
                        category=category,
                        title=title,
                        description=description,
                        recommendation=recommendation,
                        evidence={
                            "path": js_file.path,
                            "snippet": _snippet(compact_text, match.start(), match.end()),
                        },
                        confidence=round(conf, 2),
                    )
                )
                seen_rule_ids.add(rule_id)

        entropy = shannon_entropy(text[:250000])
        minified_ratio = _minified_ratio(text)

        if (BASE64_RE.search(text) or HEX_BLOB_RE.search(text)) and js_file.size > 50000:
            findings.append(
                finding(
                    rule_id="JS_ENCODED_PAYLOAD",
                    severity="medium",
                    category="Obfuscation",
                    title="Large encoded payload found in JavaScript",
                    description="Large base64 or hexadecimal blobs can conceal staged payloads or opaque bundled logic.",
                    recommendation="Require source review and remove opaque encoded payloads.",
                    evidence={"path": js_file.path},
                    confidence=0.58,
                )
            )

        if js_file.size > 25000 and entropy >= 5.25 and minified_ratio >= 0.72:
            findings.append(
                finding(
                    rule_id="JS_HIGH_ENTROPY_MINIFIED",
                    severity="low",
                    category="Obfuscation",
                    title="High-entropy minified JavaScript",
                    description="Dense high-entropy code reduces reviewability.",
                    recommendation="Request readable source before approval.",
                    evidence={
                        "path": js_file.path,
                        "entropy": round(entropy, 3),
                        "minified_ratio": round(minified_ratio, 3),
                    },
                    confidence=0.52,
                )
            )

        miner_hits = len(re.findall(r"(?i)(coinhive|cryptonight|stratum\+tcp|minergate)", text))
        websocket_miner = re.search(r"(?i)(new\s+WebSocket\(|socket\.send\().{0,120}(coinhive|stratum|mining)", compact_text)
        if miner_hits >= 2 and websocket_miner:
            findings.append(
                finding(
                    rule_id="JS_CRYPTO_MINER",
                    severity="high",
                    category="Malware",
                    title="Potential unauthorized compute-mining behavior",
                    description="Multiple miner-specific references coincide with active socket communication patterns.",
                    recommendation="Validate whether bundled code performs unauthorized background computation.",
                    evidence={"path": js_file.path, "hits": miner_hits},
                    confidence=0.72,
                )
            )

    metadata = {
        "js_file_count": scanned_files,
        "js_total_bytes": total_bytes,
        "js_total_lines": total_lines,
        "external_urls": unique_preserve(urls)[:80],
        "largest_js_file": largest_file,
    }
    return findings, metadata


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 90)
    right = min(len(text), end + 90)
    return text[left:right].strip()[:260]


def _minified_ratio(text: str) -> float:
    if not text:
        return 0.0
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return 0.0
    long_lines = sum(1 for line in lines if len(line) > 220)
    return long_lines / len(lines)
