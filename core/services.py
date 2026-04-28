from __future__ import annotations

from pathlib import Path
from typing import Any, BinaryIO

from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from scanner.communication_analyzer import analyze_communications
from scanner.file_handler import prepare_upload
from scanner.js_analyzer import analyze_javascript
from scanner.manifest_analyzer import analyze_manifest
from scanner.report_generator import generate_pdf_report
from scanner.scoring_engine import SEVERITY_WEIGHTS, score_findings
from scanner.utils import finding

from .models import AuditEvent, BrowserExtension, Finding, Membership, Organization, Report, ScanRun


def get_active_organization(request) -> Organization | None:
    organization_id = request.session.get("active_organization_id")
    memberships = request.user.memberships.select_related("organization")
    if organization_id:
        match = memberships.filter(organization_id=organization_id).first()
        if match:
            return match.organization
    first_membership = memberships.first()
    if first_membership:
        request.session["active_organization_id"] = first_membership.organization_id
        return first_membership.organization
    return None


def ensure_user_organization(user: User) -> Organization:
    membership = user.memberships.select_related("organization").first()
    if membership:
        return membership.organization
    org_name = f"{user.get_full_name() or user.email or user.username} Workspace"
    organization = Organization.objects.create(name=org_name)
    Membership.objects.create(user=user, organization=organization, role="owner")
    return organization


def public_forensic_organization() -> Organization:
    organization, _ = Organization.objects.get_or_create(
        slug="forensic-intake",
        defaults={
            "name": "Forensic Intake Lab",
            "plan": "enterprise",
            "risk_tolerance": 35,
        },
    )
    return organization


def client_ip(request) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def audit(
    *,
    organization: Organization | None,
    user: User | None,
    action: str,
    target: str = "",
    request=None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent.objects.create(
        organization=organization,
        user=user if getattr(user, "is_authenticated", False) else None,
        action=action,
        target=target,
        ip_address=client_ip(request) if request is not None else None,
        metadata=metadata or {},
    )


@transaction.atomic
def run_zip_forensic_scan(
    *,
    organization: Organization,
    uploaded_file: BinaryIO,
    user: User | None = None,
    analyst_note: str = "",
    request=None,
) -> ScanRun:
    original_name = getattr(uploaded_file, "name", "extension.zip")
    extracted = prepare_upload(uploaded_file, original_name)
    all_findings: list[dict] = []
    metadata: dict[str, Any] = {
        "artifact": {
            "original_name": extracted.original_name,
            "archive_sha256": extracted.archive_sha256,
            "archive_size": extracted.archive_size,
            "file_count": len(extracted.files),
            "manifest_path": extracted.manifest_path,
            "warnings": extracted.warnings,
            "errors": extracted.errors,
            "analyst_note": analyst_note,
        },
        "manifest": {},
        "javascript": {},
        "communications": {},
    }

    for warning in extracted.warnings:
        all_findings.append(
            finding(
                rule_id="ARCHIVE_WARNING",
                severity="low",
                category="Archive",
                title="Archive extraction warning",
                description=warning,
                recommendation="Review acquisition integrity and confirm the package source.",
                evidence={"warning": warning},
                confidence=0.55,
            )
        )

    for error in extracted.errors:
        all_findings.append(
            finding(
                rule_id="ARCHIVE_PARSE_FAILURE",
                severity="medium",
                category="Archive",
                title="Archive could not be fully analyzed",
                description=error,
                recommendation="Re-acquire the Chrome extension package and retry analysis.",
                evidence={"error": error, "sha256": extracted.archive_sha256},
                confidence=0.75,
            )
        )

    if extracted.manifest:
        manifest_findings, manifest_meta = analyze_manifest(extracted.manifest, extracted.manifest_path)
        js_findings, js_meta = analyze_javascript(extracted.js_files)
        communication_findings, communication_meta = analyze_communications(extracted.files, extracted.manifest)
        all_findings.extend(manifest_findings)
        all_findings.extend(js_findings)
        all_findings.extend(communication_findings)
        metadata["manifest"] = manifest_meta
        metadata["javascript"] = js_meta
        metadata["communications"] = communication_meta
    elif not all_findings:
        all_findings.append(
            finding(
                rule_id="NO_ANALYZABLE_DATA",
                severity="low",
                category="Archive",
                title="No analyzable extension data found",
                description="The upload did not contain readable Chrome extension artifacts.",
                recommendation="Upload a ZIP package containing manifest.json and extension source files.",
                evidence={"sha256": extracted.archive_sha256},
                confidence=0.7,
            )
        )

    score = score_findings(all_findings, metadata)
    extension_name = metadata["manifest"].get("name") or Path(original_name).stem or "Unknown Extension"
    oauth2 = extracted.manifest.get("oauth2") if isinstance(extracted.manifest.get("oauth2"), dict) else {}
    extension_id = str(
        extracted.manifest.get("key")
        or oauth2.get("client_id")
        or extracted.archive_sha256[:24]
    )
    version = metadata["manifest"].get("version", "")
    extension_status = "quarantined" if score["risk_score"] >= 85 else "monitored"

    extension, _created = BrowserExtension.objects.update_or_create(
        organization=organization,
        extension_id=extension_id,
        defaults={
            "name": extension_name,
            "publisher": "Forensic artifact",
            "store": "chrome",
            "version": version,
            "install_base": 0,
            "manifest": {
                "raw": extracted.manifest,
                "forensics": metadata,
                "score": score,
            },
            "status": extension_status,
        },
    )
    scan = ScanRun.objects.create(
        organization=organization,
        extension=extension,
        name=f"{extension.name} forensic detonation",
        source="manual",
        status="completed",
        risk_score=score["risk_score"],
        summary=f"{score['verdict']}. {score['narrative']}",
        severity_distribution=score["severity_counts"],
        started_at=timezone.now(),
        completed_at=timezone.now(),
    )
    Finding.objects.bulk_create(
        [
            Finding(
                organization=organization,
                scan_run=scan,
                extension=extension,
                severity=item.get("severity", "info"),
                category=item.get("category", "Forensics"),
                title=item.get("title", "Static indicator"),
                description=item.get("description", ""),
                recommendation=item.get("recommendation", ""),
                evidence={
                    **(item.get("evidence") or {}),
                    "rule_id": item.get("rule_id", ""),
                    "confidence": item.get("confidence", 0.0),
                },
                risk_points=SEVERITY_WEIGHTS.get(item.get("severity", "info"), 1),
            )
            for item in all_findings
        ]
    )

    report_path = _pdf_report_path(organization, scan, extracted.archive_sha256)
    generate_pdf_report(
        {
            "scan_id": scan.id,
            "findings": all_findings,
            "metadata": metadata,
            "score": score,
        },
        report_path,
    )
    Report.objects.create(
        organization=organization,
        scan_run=scan,
        report_type="technical",
        title=f"{extension.name} Forensic Intelligence Report",
        file_path=str(report_path.relative_to(settings.BASE_DIR)),
        generated_by=user if getattr(user, "is_authenticated", False) else None,
    )

    extension.latest_risk_score = score["risk_score"]
    extension.last_scanned_at = scan.completed_at
    extension.status = extension_status
    extension.save(update_fields=["latest_risk_score", "last_scanned_at", "status", "updated_at"])
    audit(
        organization=organization,
        user=user,
        action="forensic_scan.completed",
        target=extension.name,
        request=request,
        metadata={
            "scan_id": scan.id,
            "risk_score": score["risk_score"],
            "archive_sha256": extracted.archive_sha256,
        },
    )
    extracted.cleanup()
    return scan


def organization_from_api_token(token: str | None) -> Organization | None:
    if not token:
        return None
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return Organization.objects.filter(api_token=token).first()


def _pdf_report_path(organization: Organization, scan: ScanRun, archive_sha256: str) -> Path:
    report_root = Path(settings.EXTENSIONSENTRY_REPORT_ROOT)
    report_root.mkdir(parents=True, exist_ok=True)
    timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
    return report_root / f"{organization.slug}-forensic-{scan.id}-{archive_sha256[:10]}-{timestamp}.pdf"
