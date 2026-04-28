from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import ScanRun
from .services import (
    ensure_user_organization,
    get_active_organization,
    organization_from_api_token,
    public_forensic_organization,
    run_zip_forensic_scan,
)


@require_GET
def api_health(request):
    return JsonResponse({"status": "ok", "service": "ExtensionSentry"})


@require_GET
def api_metrics(request):
    organization = _api_organization(request)
    return JsonResponse(
        {
            "organization": organization.slug,
            "extensions": organization.extensions.count(),
            "scans": organization.scans.count(),
            "open_findings": organization.findings.exclude(
                status__in=["remediated", "false_positive"]
            ).count(),
        }
    )


@csrf_exempt
@require_POST
def api_scan_create(request):
    organization = _api_organization(request)
    archive = request.FILES.get("archive")
    if archive is None:
        return JsonResponse({"error": "Upload a multipart file field named archive."}, status=400)
    scan = run_zip_forensic_scan(
        organization=organization,
        uploaded_file=archive,
        analyst_note=request.POST.get("analyst_note", ""),
        user=request.user if request.user.is_authenticated else None,
        request=request,
    )
    return JsonResponse(_scan_payload(scan), status=201)


@require_GET
def api_scan_detail(request, scan_id: int):
    organization = _api_organization(request)
    scan = ScanRun.objects.filter(pk=scan_id, organization=organization).first()
    if scan is None:
        return JsonResponse({"error": "Not found"}, status=404)
    return JsonResponse(_scan_payload(scan))


def _api_organization(request):
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    organization = organization_from_api_token(auth_header)
    if organization:
        return organization
    if request.user.is_authenticated:
        return get_active_organization(request) or ensure_user_organization(request.user)
    return public_forensic_organization()


def _scan_payload(scan: ScanRun) -> dict:
    findings = [
        {
            "id": finding.id,
            "severity": finding.severity,
            "category": finding.category,
            "title": finding.title,
            "status": finding.status,
            "risk_points": finding.risk_points,
        }
        for finding in scan.findings.all()
    ]
    return {
        "id": scan.id,
        "name": scan.name,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "threat_level": scan.extension.manifest.get("score", {}).get("threat_level", "unknown")
        if isinstance(scan.extension.manifest, dict)
        else "unknown",
        "summary": scan.summary,
        "severity_distribution": scan.severity_distribution,
        "extension": {
            "id": scan.extension.id,
            "name": scan.extension.name,
            "extension_id": scan.extension.extension_id,
        },
        "findings": findings,
    }
