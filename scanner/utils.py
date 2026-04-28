from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Iterable


TEXT_EXTENSIONS = {
    ".js",
    ".json",
    ".html",
    ".htm",
    ".css",
    ".txt",
    ".xml",
    ".md",
    ".map",
}

URL_RE = re.compile(
    r"""(?ix)
    \b
    (?:
        https?://
        |wss?://
        |ftp://
    )
    [^\s"'<>`\\)]+
    """
)

DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|ru|cn|top|xyz|info|biz)\b"
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_decode(data: bytes, limit: int | None = None) -> str:
    if limit is not None:
        data = data[:limit]
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            continue
    return data.decode("utf-8", errors="replace")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, int(value)))


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def unique_preserve(values: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def extract_urls(text: str) -> list[str]:
    return unique_preserve(match.group(0).rstrip(".,;") for match in URL_RE.finditer(text))


def extract_domains(text: str) -> list[str]:
    return unique_preserve(match.group(0).lower() for match in DOMAIN_RE.finditer(text))


def extract_ips(text: str) -> list[str]:
    ips = []
    for match in IP_RE.finditer(text):
        octets = match.group(0).split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            ips.append(match.group(0))
    return unique_preserve(ips)


def finding(
    *,
    rule_id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: dict | None = None,
    confidence: float = 0.7,
) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence or {},
        "confidence": round(confidence, 2),
    }


def file_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".js":
        return "javascript"
    if suffix == ".json":
        return "json"
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix in TEXT_EXTENSIONS:
        return "text"
    return "binary"

