from django.contrib import admin

from .models import (
    AuditEvent,
    BrowserExtension,
    Finding,
    Integration,
    Membership,
    Organization,
    Report,
    ScanRun,
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "plan", "risk_tolerance", "created_at")
    search_fields = ("name", "slug")
    readonly_fields = ("api_token", "created_at", "updated_at")


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("role",)
    search_fields = ("user__username", "user__email", "organization__name")


@admin.register(BrowserExtension)
class BrowserExtensionAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "extension_id",
        "organization",
        "store",
        "status",
        "latest_risk_score",
        "last_scanned_at",
    )
    list_filter = ("store", "status")
    search_fields = ("name", "extension_id", "publisher", "organization__name")
    readonly_fields = ("created_at", "updated_at", "last_scanned_at")


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    fields = ("severity", "category", "title", "status", "risk_points")
    readonly_fields = ("severity", "category", "title", "risk_points")


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("name", "extension", "organization", "status", "risk_score", "created_at")
    list_filter = ("status", "source")
    search_fields = ("name", "extension__name", "organization__name")
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "category", "status", "extension", "created_at")
    list_filter = ("severity", "status", "category")
    search_fields = ("title", "description", "recommendation", "extension__name")


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("title", "report_type", "organization", "generated_by", "generated_at")
    list_filter = ("report_type",)
    search_fields = ("title", "scan_run__name", "organization__name")


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "organization", "enabled", "updated_at")
    list_filter = ("provider", "enabled")
    search_fields = ("name", "endpoint_url", "organization__name")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("action", "target", "organization", "user", "ip_address", "created_at")
    list_filter = ("action",)
    search_fields = ("action", "target", "user__username", "organization__name")
    readonly_fields = ("created_at",)
