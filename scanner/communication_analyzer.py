from __future__ import annotations

from collections import Counter
from typing import Iterable

from .file_handler import ExtensionFile
from .utils import extract_domains, extract_ips, extract_urls, finding, safe_decode, unique_preserve


SUSPICIOUS_TLDS = {".ru", ".cn", ".top", ".xyz", ".biz", ".info"}
EXFIL_KEYWORDS = ("webhook", "discord", "telegram", "pastebin", "ngrok", "requestbin", "logger", "telemetry", "collect", "shadow")
TRUSTED_COMMON_DOMAINS = ("google.com", "gstatic.com", "googleusercontent.com", "mozilla.org", "microsoft.com", "githubusercontent.com", "cloudflare.com", "getadblock.com", "adblockplus.org", "easylist")


def analyze_communications(files: Iterable[ExtensionFile], manifest: dict) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []

    manifest_text = str(manifest)
    urls.extend(extract_urls(manifest_text))
    domains.extend(extract_domains(manifest_text))
    ips.extend(extract_ips(manifest_text))

    for file in files:
        if file.kind == "binary" or file.size > 2 * 1024 * 1024:
            continue
        try:
            text = safe_decode(file.absolute_path.read_bytes(), limit=2 * 1024 * 1024)
        except OSError:
            continue
        urls.extend(extract_urls(text))
        domains.extend(extract_domains(text))
        ips.extend(extract_ips(text))

    urls = [u for u in unique_preserve(urls) if len(u) < 160][:20]
    domains = [d for d in unique_preserve(domains) if not any(t in d for t in TRUSTED_COMMON_DOMAINS)][:15]
    ips = unique_preserve(ips)[:10]

    insecure_urls = [url for url in urls if url.lower().startswith("http://")]
    websocket_urls = [url for url in urls if url.lower().startswith(("ws://", "wss://"))]
    suspicious_domains = [
        domain
        for domain in domains
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        or any(keyword in domain for keyword in EXFIL_KEYWORDS)
    ]

    if insecure_urls:
        findings.append(
            finding(
                rule_id="COMMS_INSECURE_HTTP",
                severity="medium",
                category="Network",
                title="Insecure HTTP endpoint references",
                description="The extension references endpoints that can be intercepted or modified in transit.",
                recommendation="Use HTTPS for all remote endpoints.",
                evidence={"sample_urls": insecure_urls[:5], "count": len(insecure_urls)},
                confidence=0.78,
            )
        )

    if websocket_urls:
        findings.append(
            finding(
                rule_id="COMMS_WEBSOCKET",
                severity="low",
                category="Network",
                title="WebSocket communication endpoints detected",
                description="Persistent WebSocket channels were observed in static references.",
                recommendation="Validate endpoint ownership and message schemas.",
                evidence={"sample_urls": websocket_urls[:5], "count": len(websocket_urls)},
                confidence=0.58,
            )
        )

    if len(ips) >= 2:
        findings.append(
            finding(
                rule_id="COMMS_IP_LITERAL",
                severity="medium",
                category="Network",
                title="IP literal network destinations detected",
                description="Hard-coded IP destinations bypass domain ownership controls.",
                recommendation="Investigate IP ownership and replace literals with approved domains.",
                evidence={"ips": ips[:8], "count": len(ips)},
                confidence=0.66,
            )
        )

    if suspicious_domains:
        findings.append(
            finding(
                rule_id="COMMS_SUSPICIOUS_DOMAIN",
                severity="medium",
                category="Network",
                title="Suspicious external domain indicators",
                description="The extension references domains with risky TLDs or exfiltration-service keywords.",
                recommendation="Validate ownership before deployment.",
                evidence={"domains": suspicious_domains[:8], "count": len(suspicious_domains)},
                confidence=0.62,
            )
        )

    domain_counts = Counter(domain.rsplit(".", 2)[-1] for domain in domains)
    metadata = {
        "url_count": len(urls),
        "domain_count": len(domains),
        "ip_count": len(ips),
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "tld_distribution": dict(domain_counts.most_common(8)),
    }
    return findings, metadata
