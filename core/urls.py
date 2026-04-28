from django.urls import path

from . import api, views


urlpatterns = [
    path("console/", views.scan_console, name="scan_console"),
    path("processing/<int:scan_id>/", views.scan_processing, name="scan_processing"),
    path("results/<int:scan_id>/", views.forensic_results, name="forensic_results"),
    path("threat-lab/", views.threat_lab, name="threat_lab"),
    path("reports/<int:report_id>/download/", views.download_report, name="download_report"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("extensions/", views.extension_list, name="extension_list"),
    path("extensions/<int:pk>/", views.extension_detail, name="extension_detail"),
    path("scans/new/", views.scan_new, name="scan_new"),
    path("scans/<int:pk>/", views.scan_detail, name="scan_detail"),
    path("reports/", views.reports, name="reports"),
    path("reports/generate/<int:scan_id>/", views.report_generate, name="report_generate"),
    path("integrations/", views.integrations, name="integrations"),
    path("audit/", views.audit_log, name="audit_log"),
    path("settings/organization/", views.organization_settings, name="organization_settings"),
    path("settings/switch-organization/", views.switch_organization, name="switch_organization"),
    path("api/v1/health/", api.api_health, name="api_health"),
    path("api/v1/metrics/", api.api_metrics, name="api_metrics"),
    path("api/v1/scans/", api.api_scan_create, name="api_scan_create"),
    path("api/v1/scans/<int:scan_id>/", api.api_scan_detail, name="api_scan_detail"),
]
