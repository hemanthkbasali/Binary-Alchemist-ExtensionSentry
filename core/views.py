from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.db.models import Avg
from django.db import transaction
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from scanner.scoring_engine import SEVERITY_WEIGHTS

from .forms import ExtensionZipUploadForm, SignupForm
from .models import AuditEvent, Finding, Membership, Organization, Report, ScanRun
from .services import audit, ensure_user_organization, get_active_organization, public_forensic_organization, run_zip_forensic_scan


def home(request):
    organization = _workspace(request)
    reports = Report.objects.filter(organization=organization).select_related("scan_run", "scan_run__extension").order_by("-generated_at")
    scans = ScanRun.objects.filter(organization=organization).select_related("extension").order_by("-created_at")
    findings = Finding.objects.filter(organization=organization)
    latest_scan = scans.first()
    latest_report = reports.first()

    avg_risk = int(scans.aggregate(value=Avg("risk_score")).get("value") or 0)
    high_risk_count = scans.filter(risk_score__gte=70).count()
    total_indicators = findings.count()
    dangerous_permission_total = _dangerous_permission_total(scans)
    total_scans = scans.count()

    manifest_avg = _category_average(findings, ["manifest", "permission", "host"])
    js_avg = _category_average(findings, ["javascript", "js", "script", "obfuscation"])
    ioc_avg = _category_average(findings, ["communication", "comms", "network", "ioc", "domain", "url"])

    pipeline = _pipeline_completion(scans[:12])
    event_log = _home_event_log(organization)
    latest_score = (latest_scan.extension.manifest or {}).get("score", {}) if latest_scan else {}

    return render(
        request,
        "core/landing.html",
        {
            "latest_scan": latest_scan,
            "home_metrics": {
                "total_scans": total_scans,
                "high_risk_count": high_risk_count,
                "avg_risk": avg_risk,
                "total_indicators": total_indicators,
                "dangerous_permissions": dangerous_permission_total,
            },
            "latest_case": {
                "name": latest_scan.extension.name if latest_scan else "NO CASE",
                "risk": latest_scan.risk_score if latest_scan else 0,
                "verdict": latest_score.get("verdict", "NO VERDICT"),
                "timestamp": latest_scan.created_at if latest_scan else None,
                "report_ready": bool(latest_report and latest_scan and latest_report.scan_run_id == latest_scan.id),
            },
            "engine_dials": {
                "manifest": manifest_avg,
                "js": js_avg,
                "ioc": ioc_avg,
            },
            "pipeline": pipeline,
            "event_log": event_log,
        },
    )


@transaction.atomic
def signup(request):
    if request.user.is_authenticated:
        return redirect("scan_console")
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            organization = Organization.objects.create(name=form.cleaned_data["organization_name"])
            Membership.objects.create(user=user, organization=organization, role="owner")
            login(request, user)
            request.session["active_organization_id"] = organization.id
            audit(organization=organization, user=user, action="lab.signup", target=organization.name, request=request)
            return redirect("scan_console")
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})


def scan_console(request):
    organization = _workspace(request)
    if request.method == "POST":
        form = ExtensionZipUploadForm(request.POST, request.FILES)
        if form.is_valid():
            scan = run_zip_forensic_scan(
                organization=organization,
                uploaded_file=form.cleaned_data["archive"],
                analyst_note=form.cleaned_data.get("analyst_note", ""),
                user=request.user if request.user.is_authenticated else None,
                request=request,
            )
            request.session["latest_scan_id"] = scan.id
            return redirect("scan_processing", scan_id=scan.id)
        messages.error(request, "Archive rejected by intake validation.")
    else:
        form = ExtensionZipUploadForm()
    recent_scans = organization.scans.select_related("extension").order_by("-created_at")[:6]
    risk_values = [scan.risk_score for scan in recent_scans]
    queue_avg = int(sum(risk_values) / len(risk_values)) if risk_values else 0
    queue_max = max(risk_values) if risk_values else 0
    return render(
        request,
        "core/scan_console.html",
        {
            "form": form,
            "recent_scans": recent_scans,
            "organization": organization,
            "queue_metrics": {
                "count": len(recent_scans),
                "avg_risk": queue_avg,
                "max_risk": queue_max,
                "position_next": len(recent_scans) + 1,
            },
        },
    )


def scan_processing(request, scan_id: int):
    scan = get_object_or_404(ScanRun.objects.select_related("extension"), pk=scan_id)
    telemetry = _scan_telemetry(scan)
    stage_log = _processing_stage_log(scan)
    return render(
        request,
        "core/processing.html",
        {
            "scan": scan,
            "telemetry": telemetry,
            "stage_log": stage_log,
            "processing_progress_target": 100 if scan.status == "completed" else 72,
        },
    )


def forensic_results(request, scan_id: int):
    scan = get_object_or_404(ScanRun.objects.select_related("extension", "organization"), pk=scan_id)
    findings = scan.findings.all()
    metadata = scan.extension.manifest.get("forensics", {}) if isinstance(scan.extension.manifest, dict) else {}
    score = scan.extension.manifest.get("score", {}) if isinstance(scan.extension.manifest, dict) else {}
    report = scan.reports.order_by("-generated_at").first()
    high_signal = findings.filter(severity__in=["critical", "high"])[:8]
    total_findings = max(findings.count(), 1)
    severity_widths = {
        severity: int((scan.severity_distribution.get(severity, 0) / total_findings) * 100)
        for severity in ["critical", "high", "medium", "low", "info"]
    }
    results_graph_nodes = _results_graph_nodes(scan.extension.name, metadata, findings)
    return render(
        request,
        "core/results_dashboard.html",
        {
            "scan": scan,
            "findings": findings,
            "high_signal": high_signal,
            "metadata": metadata,
            "score": score,
            "report": report,
            "telemetry": _scan_telemetry(scan),
            "severity_order": ["critical", "high", "medium", "low", "info"],
            "severity_widths": severity_widths,
            "results_graph_nodes": results_graph_nodes,
        },
    )


def threat_lab(request):
    organization = _workspace(request)
    recent_scans = organization.scans.select_related("extension").order_by("-created_at")[:10]
    findings = Finding.objects.filter(organization=organization)
    scans = ScanRun.objects.filter(organization=organization)
    reports = Report.objects.filter(organization=organization)

    rules = _rule_matrix(findings)
    permission_hits = _top_permissions(scans)
    domain_hits = _top_domains(scans)
    recent_extensions = [scan.extension.name for scan in recent_scans[:3]]
    avg_global_score = int(scans.aggregate(value=Avg("risk_score")).get("value") or 0)
    diagnostics_log = _threat_lab_diagnostics(organization, scans, findings)
    health = _engine_health(scans, findings)
    return render(
        request,
        "core/threat_lab.html",
        {
            "recent_scans": recent_scans,
            "rules": rules,
            "permission_hits": permission_hits,
            "domain_hits": domain_hits,
            "history_total": reports.count(),
            "avg_global_score": avg_global_score,
            "recent_extensions": recent_extensions,
            "diagnostics_log": diagnostics_log,
            "engine_health": health,
        },
    )


def download_report(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    path = (settings.BASE_DIR / report.file_path).resolve()
    try:
        path.relative_to(settings.BASE_DIR.resolve())
    except ValueError as exc:
        raise Http404("Report path rejected") from exc
    if not path.exists():
        raise Http404("Report file not found")
    return FileResponse(path.open("rb"), as_attachment=True, filename=Path(report.file_path).name)


def dashboard(request):
    scan_id = request.session.get("latest_scan_id")
    if scan_id and ScanRun.objects.filter(pk=scan_id).exists():
        return redirect("forensic_results", scan_id=scan_id)
    latest_scan = ScanRun.objects.order_by("-created_at").first()
    if latest_scan:
        return redirect("forensic_results", scan_id=latest_scan.id)
    return redirect("scan_console")


def scan_new(request):
    return scan_console(request)


def scan_detail(request, pk: int):
    return redirect("forensic_results", scan_id=pk)


def extension_list(request):
    return redirect("threat_lab")


def extension_detail(request, pk: int):
    scan = ScanRun.objects.filter(extension_id=pk).order_by("-created_at").first()
    if scan:
        return redirect("forensic_results", scan_id=scan.id)
    return redirect("threat_lab")


def reports(request):
    return redirect("threat_lab")


def report_generate(request, scan_id: int):
    return redirect("forensic_results", scan_id=scan_id)


def integrations(request):
    return redirect("threat_lab")


def audit_log(request):
    return redirect("threat_lab")


def organization_settings(request):
    return redirect("threat_lab")


def switch_organization(request):
    return redirect("scan_console")


def _workspace(request) -> Organization:
    if request.user.is_authenticated:
        organization = get_active_organization(request)
        if organization is None:
            organization = ensure_user_organization(request.user)
            request.session["active_organization_id"] = organization.id
        return organization
    return public_forensic_organization()


def _scan_telemetry(scan: ScanRun) -> dict:
    metadata = scan.extension.manifest.get("forensics", {}) if isinstance(scan.extension.manifest, dict) else {}
    artifact = metadata.get("artifact", {})
    javascript = metadata.get("javascript", {})
    communications = metadata.get("communications", {})
    counts = scan.severity_distribution or {}
    return {
        "files": artifact.get("file_count", 0),
        "js_files": javascript.get("js_file_count", 0),
        "urls": min(int(communications.get("url_count", 0)), 20),
        "domains": min(int(communications.get("domain_count", 0)), 15),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "sha256": artifact.get("archive_sha256", "")[:16],
    }


def _severity_numeric(severity: str) -> int:
    return {
        "critical": 100,
        "high": 80,
        "medium": 55,
        "low": 30,
        "info": 15,
    }.get((severity or "").lower(), 15)


def _category_average(findings_qs, needles: list[str]) -> int:
    values = []
    for item in findings_qs.only("severity", "category"):
        category = (item.category or "").lower()
        if any(n in category for n in needles):
            values.append(_severity_numeric(item.severity))
    return int(sum(values) / len(values)) if values else 0


def _dangerous_permission_total(scans_qs) -> int:
    dangerous = {
        "debugger", "management", "proxy", "tabs", "cookies", "webrequest", "webrequestblocking",
        "nativeMessaging", "history", "downloads", "clipboardRead", "clipboardWrite",
    }
    count = 0
    for scan in scans_qs:
        manifest = (scan.extension.manifest or {}).get("forensics", {}).get("manifest", {})
        perms = manifest.get("permissions", []) or []
        count += sum(1 for p in perms if str(p) in dangerous)
    return count


def _pipeline_completion(scans_qs) -> dict:
    total = len(scans_qs)
    if total == 0:
        return {"intake": 0, "manifest": 0, "js": 0, "report": 0}
    intake = manifest = js = report = 0
    for scan in scans_qs:
        forensics = (scan.extension.manifest or {}).get("forensics", {})
        intake += 1 if forensics.get("artifact") else 0
        manifest += 1 if forensics.get("manifest") else 0
        js += 1 if forensics.get("javascript") else 0
        report += 1 if scan.reports.exists() else 0
    return {
        "intake": int(intake * 100 / total),
        "manifest": int(manifest * 100 / total),
        "js": int(js * 100 / total),
        "report": int(report * 100 / total),
    }


def _home_event_log(organization: Organization) -> list[str]:
    events = list(
        AuditEvent.objects.filter(organization=organization, action__startswith="forensic_scan.")
        .order_by("-created_at")
        .values_list("target", "metadata", "created_at")[:6]
    )
    logs = []
    for target, metadata, created_at in events:
        risk = (metadata or {}).get("risk_score", 0)
        logs.append(f"> {created_at:%H:%M} {target} risk:{risk}")
    return logs or ["> idle: waiting for next artifact"]


def _processing_stage_log(scan: ScanRun) -> list[str]:
    manifest = (scan.extension.manifest or {}).get("forensics", {})
    artifact = manifest.get("artifact", {})
    m = manifest.get("manifest", {})
    js = manifest.get("javascript", {})
    comms = manifest.get("communications", {})
    score = (scan.extension.manifest or {}).get("score", {})
    return [
        f"archive unpacked: files={artifact.get('file_count', 0)}",
        f"manifest parsed: version={m.get('version', 'unknown')}",
        f"permissions indexed: count={len(m.get('permissions', []) or [])}",
        f"javascript behavior mapped: js_files={js.get('js_file_count', 0)}",
        f"ioc extraction complete: urls={comms.get('url_count', 0)} domains={comms.get('domain_count', 0)}",
        f"score synthesis complete: risk={score.get('risk_score', scan.risk_score)}",
    ]


def _results_graph_nodes(extension_name: str, metadata: dict, findings_qs) -> list[str]:
    nodes = [extension_name]
    comms = metadata.get("communications", {})
    clean_domains = [d for d in (comms.get("domains") or []) if "." in str(d)][:10]
    nodes.extend(clean_domains)
    return nodes[:10]


def _rule_matrix(findings_qs) -> list[tuple[str, str, str, int]]:
    buckets = {
        "MANIFEST": ["manifest", "permission", "host"],
        "JS": ["javascript", "script", "obfuscation", "execution"],
        "COMMS": ["communication", "network", "domain", "url", "ip"],
        "ARCHIVE": ["archive"],
    }
    out = []
    for code, needles in buckets.items():
        relevant = [f for f in findings_qs if any(n in (f.category or "").lower() for n in needles)]
        avg = int(sum(_severity_numeric(f.severity) for f in relevant) / len(relevant)) if relevant else 0
        out.append((code, f"{len(relevant)} hits", f"avg severity {avg}", avg))
    score_weight = ", ".join(f"{key}:{value}" for key, value in SEVERITY_WEIGHTS.items())
    out.append(("SCORING", "severity weights", score_weight, 100))
    return out


def _top_permissions(scans_qs) -> list[tuple[str, int]]:
    counts = {}
    for scan in scans_qs:
        perms = ((scan.extension.manifest or {}).get("forensics", {}).get("manifest", {}).get("permissions", []) or [])
        for perm in perms:
            key = str(perm)
            counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda pair: pair[1], reverse=True)[:6]


def _top_domains(scans_qs) -> list[tuple[str, int]]:
    counts = {}
    for scan in scans_qs:
        domains = ((scan.extension.manifest or {}).get("forensics", {}).get("communications", {}).get("domains", []) or [])
        for domain in domains:
            key = str(domain)
            counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda pair: pair[1], reverse=True)[:6]


def _threat_lab_diagnostics(organization: Organization, scans_qs, findings_qs) -> list[str]:
    day_ago = timezone.now() - timezone.timedelta(hours=24)
    recent_scan_count = scans_qs.filter(created_at__gte=day_ago).count()
    recent_critical = findings_qs.filter(created_at__gte=day_ago, severity="critical").count()
    avg_risk = int(scans_qs.aggregate(v=Avg("risk_score")).get("v") or 0)
    return [
        f"> queue_24h scans={recent_scan_count}",
        f"> critical_24h findings={recent_critical}",
        f"> avg_global_score={avg_risk}",
        f"> history_total={Report.objects.filter(organization=organization).count()}",
    ]


def _engine_health(scans_qs, findings_qs) -> dict:
    scans_total = scans_qs.count()
    return {
        "archive": 100 if scans_total else 0,
        "manifest": min(100, findings_qs.filter(category__icontains="manifest").count() * 5),
        "js": min(100, findings_qs.filter(category__icontains="javascript").count() * 5),
        "ioc": min(100, findings_qs.filter(category__icontains="communication").count() * 5),
        "scoring": 100 if scans_total else 0,
        "pdf": min(100, Report.objects.filter(scan_run__in=scans_qs).count() * 10),
    }
