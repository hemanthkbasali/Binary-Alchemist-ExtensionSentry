from __future__ import annotations

import secrets

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils.text import slugify


def generate_api_token() -> str:
    return secrets.token_urlsafe(32)


class Organization(models.Model):
    PLAN_CHOICES = [
        ("starter", "Starter"),
        ("growth", "Growth"),
        ("enterprise", "Enterprise"),
    ]

    name = models.CharField(max_length=160)
    slug = models.SlugField(max_length=180, unique=True, blank=True)
    plan = models.CharField(max_length=32, choices=PLAN_CHOICES, default="starter")
    risk_tolerance = models.PositiveSmallIntegerField(
        default=70,
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        help_text="Maximum acceptable extension risk score before escalation.",
    )
    api_token = models.CharField(max_length=128, unique=True, default=generate_api_token)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        if not self.slug:
            base_slug = slugify(self.name) or "organization"
            candidate = base_slug
            counter = 2
            while type(self).objects.filter(slug=candidate).exclude(pk=self.pk).exists():
                candidate = f"{base_slug}-{counter}"
                counter += 1
            self.slug = candidate
        super().save(*args, **kwargs)

    def rotate_api_token(self) -> str:
        self.api_token = generate_api_token()
        self.save(update_fields=["api_token", "updated_at"])
        return self.api_token


class Membership(models.Model):
    ROLE_CHOICES = [
        ("owner", "Owner"),
        ("admin", "Admin"),
        ("analyst", "Analyst"),
        ("viewer", "Viewer"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.CharField(max_length=32, choices=ROLE_CHOICES, default="analyst")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["user", "organization"]
        ordering = ["organization__name", "user__email"]

    def __str__(self) -> str:
        return f"{self.user} @ {self.organization} ({self.role})"


class BrowserExtension(models.Model):
    STORE_CHOICES = [
        ("chrome", "Chrome Web Store"),
        ("edge", "Microsoft Edge Add-ons"),
        ("firefox", "Firefox Add-ons"),
        ("internal", "Internal Package"),
    ]

    STATUS_CHOICES = [
        ("monitored", "Monitored"),
        ("quarantined", "Quarantined"),
        ("approved", "Approved"),
        ("retired", "Retired"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="extensions",
    )
    name = models.CharField(max_length=220)
    extension_id = models.CharField(max_length=128)
    publisher = models.CharField(max_length=220, blank=True)
    store = models.CharField(max_length=32, choices=STORE_CHOICES, default="chrome")
    version = models.CharField(max_length=64, blank=True)
    install_base = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="monitored")
    manifest = models.JSONField(default=dict, blank=True)
    latest_risk_score = models.PositiveSmallIntegerField(default=0)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["organization", "extension_id"]
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("extension_detail", kwargs={"pk": self.pk})


class ScanRun(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    SOURCE_CHOICES = [
        ("manual", "Manual"),
        ("scheduled", "Scheduled"),
        ("api", "API"),
        ("seed", "Seed"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="scans",
    )
    extension = models.ForeignKey(
        BrowserExtension,
        on_delete=models.CASCADE,
        related_name="scans",
    )
    name = models.CharField(max_length=220)
    source = models.CharField(max_length=32, choices=SOURCE_CHOICES, default="manual")
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="queued")
    risk_score = models.PositiveSmallIntegerField(default=0)
    summary = models.TextField(blank=True)
    severity_distribution = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("scan_detail", kwargs={"pk": self.pk})


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ]

    STATUS_CHOICES = [
        ("open", "Open"),
        ("triaged", "Triaged"),
        ("accepted", "Accepted Risk"),
        ("remediated", "Remediated"),
        ("false_positive", "False Positive"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    extension = models.ForeignKey(
        BrowserExtension,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=80)
    title = models.CharField(max_length=220)
    description = models.TextField()
    recommendation = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    risk_points = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["status", "-risk_points", "-created_at"]

    def __str__(self) -> str:
        return f"{self.get_severity_display()}: {self.title}"


class Report(models.Model):
    TYPE_CHOICES = [
        ("executive", "Executive"),
        ("technical", "Technical"),
        ("compliance", "Compliance"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="reports",
    )
    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="reports",
    )
    report_type = models.CharField(max_length=32, choices=TYPE_CHOICES, default="technical")
    title = models.CharField(max_length=240)
    file_path = models.CharField(max_length=500)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="generated_reports",
        null=True,
        blank=True,
    )
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return self.title


class Integration(models.Model):
    PROVIDER_CHOICES = [
        ("slack", "Slack"),
        ("jira", "Jira"),
        ("splunk", "Splunk"),
        ("sentinel", "Microsoft Sentinel"),
        ("webhook", "Generic Webhook"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="integrations",
    )
    name = models.CharField(max_length=160)
    provider = models.CharField(max_length=32, choices=PROVIDER_CHOICES)
    endpoint_url = models.URLField(blank=True)
    enabled = models.BooleanField(default=True)
    secret_reference = models.CharField(max_length=160, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider", "name"]

    def __str__(self) -> str:
        return f"{self.get_provider_display()} - {self.name}"


class AuditEvent(models.Model):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=120)
    target = models.CharField(max_length=220, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.action} - {self.target or 'system'}"
