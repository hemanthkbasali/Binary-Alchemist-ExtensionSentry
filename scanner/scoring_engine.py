from __future__ import annotations

from collections import Counter

from .utils import clamp


SEVERITY_WEIGHTS = {
    "critical": 14,
    "high": 8,
    "medium": 4,
    "low": 1,
    "info": 0,
}


def score_findings(findings: list[dict], metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    counts = Counter(item.get("severity", "info") for item in findings)

    weighted = sum(SEVERITY_WEIGHTS.get(item.get("severity", "info"), 0) for item in findings)

    js_count = int(metadata.get("javascript", {}).get("js_file_count") or 0)
    url_count = int(metadata.get("communications", {}).get("url_count") or 0)
    file_count = int(metadata.get("artifact", {}).get("file_count") or 0)

    complexity_bonus = 0
    if js_count > 60:
        complexity_bonus += 1
    if url_count > 35:
        complexity_bonus += 1
    if file_count > 1200:
        complexity_bonus += 1

    critical_count = counts.get("critical", 0)
    high_count = counts.get("high", 0)

    score = weighted + complexity_bonus

    # soft normalization so realistic extensions don't insta-hit 100
    if score > 70:
        score = 70 + ((score - 70) * 0.35)

    # legitimacy dampening for adblock/common utility style extensions
    ext_urls = metadata.get("javascript", {}).get("external_urls") or []
    joined_urls = " ".join(ext_urls).lower()

    if any(x in joined_urls for x in ["getadblock", "adblockplus", "easylist", "filterlists", "google", "gstatic", "googleusercontent", "microsoft", "githubusercontent", "cloudflare"]):
        score *= 0.48

    # final clamp with sane lower/upper bounds
    score = int(clamp(round(score), 0, 100))

    if score >= 80:
        threat_level = "critical"
        verdict = "Quarantine recommended"
        narrative = "Multiple converging high-confidence indicators suggest severe extension risk."
    elif score >= 60:
        threat_level = "high"
        verdict = "Security review required"
        narrative = "The extension exposes elevated-risk behaviors that warrant analyst review."
    elif score >= 35:
        threat_level = "elevated"
        verdict = "Review recommended"
        narrative = "The extension shows moderate forensic concerns and should be manually reviewed."
    elif score >= 16:
        threat_level = "guarded"
        verdict = "Monitor"
        narrative = "Low-to-moderate indicators were detected. Keep the extension in monitored inventory."
    else:
        threat_level = "safe"
        verdict = "Low concern / Monitor"
        narrative = "Only minor low-confidence indicators were detected. Extension appears low risk."

    return {
        "risk_score": score,
        "threat_level": threat_level,
        "verdict": verdict,
        "narrative": narrative,
        "severity_counts": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        },
    }
