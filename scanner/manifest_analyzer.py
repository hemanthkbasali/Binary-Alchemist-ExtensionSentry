from __future__ import annotations

from typing import Any

from .utils import as_list, finding


CRITICAL_PERMISSIONS = {
    "debugger": "Attach to browser debugging targets and observe page internals.",
    "nativeMessaging": "Bridge browser code to native host applications.",
    "management": "Enumerate or interact with installed extensions; requires contextual review.",
}

HIGH_PERMISSIONS = {
    "tabs": "Read tab titles, favicons, and URLs.",
    "webRequest": "Observe network traffic.",
    "webRequestBlocking": "Modify or block network traffic.",
    "cookies": "Read or modify cookies.",
    "history": "Read browsing history.",
    "downloads": "Observe downloaded files.",
    "proxy": "Control browser proxy settings.",
    "scripting": "Inject scripts into web pages.",
    "clipboardRead": "Read clipboard content.",
    "clipboardWrite": "Write clipboard content.",
}

BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _resolve_manifest_name(manifest: dict[str, Any]) -> str:
    raw_name = str(manifest.get("name") or "").strip()
    if raw_name and not raw_name.startswith("__MSG_"):
        return raw_name

    short_name = str(manifest.get("short_name") or "").strip()
    if short_name and not short_name.startswith("__MSG_"):
        return short_name

    action = manifest.get("action") or {}
    default_title = str(action.get("default_title") or "").strip()
    if default_title and not default_title.startswith("__MSG_"):
        return default_title

    return "Analyzed Chrome Extension"


def analyze_manifest(manifest: dict[str, Any], manifest_path: str = "manifest.json") -> tuple[list[dict], dict]:
    findings: list[dict] = []
    permissions = set(str(item) for item in as_list(manifest.get("permissions")))
    optional_permissions = set(str(item) for item in as_list(manifest.get("optional_permissions")))
    host_permissions = set(str(item) for item in as_list(manifest.get("host_permissions")))
    all_permissions = permissions | optional_permissions

    version = manifest.get("manifest_version")
    if version != 3:
        findings.append(
            finding(
                rule_id="MANIFEST_LEGACY_VERSION",
                severity="medium",
                category="Manifest",
                title="Legacy or missing Manifest V3 declaration",
                description="The extension does not declare Manifest V3, reducing modern platform control and review posture.",
                recommendation="Migrate to Manifest V3 and remove deprecated background pages and blocking APIs.",
                evidence={"manifest_version": version, "path": manifest_path},
                confidence=0.9,
            )
        )

    for permission, description in sorted(CRITICAL_PERMISSIONS.items()):
        if permission in all_permissions:
            findings.append(
                finding(
                    rule_id=f"PERMISSION_CRITICAL_{permission.upper()}",
                    severity="medium",
                    category="Permission",
                    title=f"Sensitive Chrome permission declared: {permission}",
                    description=description,
                    recommendation="Confirm the permission is justified by documented extension functionality and minimize if possible.",
                    evidence={"permission": permission, "path": manifest_path},
                    confidence=0.95,
                )
            )

    for permission, description in sorted(HIGH_PERMISSIONS.items()):
        if permission in all_permissions:
            findings.append(
                finding(
                    rule_id=f"PERMISSION_HIGH_{permission.upper()}",
                    severity="medium",
                    category="Permission",
                    title=f"High-risk Chrome permission: {permission}",
                    description=description,
                    recommendation="Constrain capabilities with optional permissions and explicit user gestures.",
                    evidence={"permission": permission, "path": manifest_path},
                    confidence=0.82,
                )
            )

    broad_hosts = sorted(host_permissions.intersection(BROAD_HOSTS))
    content_matches = _content_script_matches(manifest)
    broad_content_matches = sorted(set(content_matches).intersection(BROAD_HOSTS))

    if broad_hosts:
        findings.append(
            finding(
                rule_id="HOST_ALL_URLS",
                severity="high",
                category="Host Access",
                title="Extension requests broad host access",
                description="The extension can observe or modify content across a large browsing surface.",
                recommendation="Replace broad host permissions with exact domains and optional host grants.",
                evidence={"host_permissions": broad_hosts},
                confidence=0.88,
            )
        )

    if broad_content_matches:
        findings.append(
            finding(
                rule_id="CONTENT_SCRIPT_ALL_URLS",
                severity="medium",
                category="Content Script",
                title="Content scripts inject across broad URL patterns",
                description="Automatic injection across many origins expands the data exposure boundary.",
                recommendation="Restrict content scripts to approved business domains.",
                evidence={"matches": broad_content_matches},
                confidence=0.78,
            )
        )

    externally_connectable = manifest.get("externally_connectable") or {}
    external_matches = [str(item) for item in as_list(externally_connectable.get("matches"))]
    if "*" in external_matches or "<all_urls>" in external_matches:
        findings.append(
            finding(
                rule_id="EXTERNALLY_CONNECTABLE_WILDCARD",
                severity="medium",
                category="Messaging",
                title="External messaging allows broad origins",
                description="Broad externally_connectable rules can expose privileged extension messaging to untrusted sites.",
                recommendation="Allow only exact trusted origins for external messaging.",
                evidence={"externally_connectable.matches": external_matches},
                confidence=0.74,
            )
        )

    csp = _csp_text(manifest.get("content_security_policy"))
    if "unsafe-eval" in csp:
        findings.append(
            finding(
                rule_id="CSP_UNSAFE_EVAL",
                severity="medium",
                category="CSP",
                title="Content Security Policy permits unsafe eval",
                description="Eval-like execution weakens protection against malicious dynamic code paths.",
                recommendation="Remove unsafe-eval and ship static bundled scripts.",
                evidence={"content_security_policy": csp[:400]},
                confidence=0.76,
            )
        )

    metadata = {
        "name": _resolve_manifest_name(manifest),
        "version": str(manifest.get("version") or ""),
        "manifest_version": version or "unknown",
        "permissions": sorted(permissions),
        "optional_permissions": sorted(optional_permissions),
        "host_permissions": sorted(host_permissions),
        "content_script_matches": content_matches,
    }
    return findings, metadata


def _content_script_matches(manifest: dict[str, Any]) -> list[str]:
    matches: list[str] = []
    for script in as_list(manifest.get("content_scripts")):
        if isinstance(script, dict):
            matches.extend(str(item) for item in as_list(script.get("matches")))
    return matches


def _csp_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(str(part) for part in value.values())
    return str(value or "")
