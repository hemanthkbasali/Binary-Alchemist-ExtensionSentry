from __future__ import annotations

from io import BytesIO
import json
import zipfile

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from scanner.file_handler import prepare_upload
from scanner.manifest_analyzer import analyze_manifest

from .models import Membership, Organization
from .services import run_zip_forensic_scan


def build_extension_zip(manifest: dict, files: dict[str, str] | None = None) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for path, content in (files or {}).items():
            archive.writestr(path, content)
    return stream.getvalue()


class ScannerModuleTests(TestCase):
    def test_manifest_analyzer_flags_critical_permissions(self):
        findings, metadata = analyze_manifest(
            {
                "manifest_version": 2,
                "name": "Risky",
                "permissions": ["tabs", "nativeMessaging"],
                "host_permissions": ["<all_urls>"],
            }
        )

        self.assertEqual(metadata["name"], "Risky")
        self.assertTrue(any(item["severity"] == "critical" for item in findings))
        self.assertTrue(any(item["rule_id"] == "HOST_ALL_URLS" for item in findings))

    def test_file_handler_gracefully_handles_bad_zip(self):
        uploaded = SimpleUploadedFile("bad.zip", b"not a zip", content_type="application/zip")
        extracted = prepare_upload(uploaded, "bad.zip")

        self.assertFalse(extracted.ok)
        self.assertIn("valid ZIP", extracted.errors[0])


class ForensicWorkflowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst@example.com",
            email="analyst@example.com",
            password="SecurePass123!",
        )
        self.organization = Organization.objects.create(name="Acme Security")
        Membership.objects.create(user=self.user, organization=self.organization, role="owner")

    def test_zip_scan_creates_findings_and_pdf_report(self):
        payload = build_extension_zip(
            {
                "manifest_version": 3,
                "name": "Payload Helper",
                "version": "1.0",
                "permissions": ["tabs"],
                "host_permissions": ["<all_urls>"],
            },
            {"background.js": "eval('alert(1)'); fetch('http://198.51.100.10/a')"},
        )
        scan = run_zip_forensic_scan(
            organization=self.organization,
            uploaded_file=SimpleUploadedFile("payload.zip", payload, content_type="application/zip"),
            user=self.user,
        )

        self.assertEqual(scan.status, "completed")
        self.assertGreaterEqual(scan.risk_score, 60)
        self.assertTrue(scan.findings.exists())
        report = scan.reports.first()
        self.assertIsNotNone(report)
        self.assertTrue(report.file_path.endswith(".pdf"))

    def test_malformed_upload_still_creates_safe_scan_result(self):
        scan = run_zip_forensic_scan(
            organization=self.organization,
            uploaded_file=SimpleUploadedFile("broken.zip", b"not a zip", content_type="application/zip"),
            user=self.user,
        )

        self.assertEqual(scan.status, "completed")
        self.assertGreater(scan.risk_score, 0)
        self.assertTrue(scan.findings.filter(category="Archive").exists())
        self.assertTrue(scan.reports.filter(file_path__endswith=".pdf").exists())

    def test_console_upload_flow_renders_processing(self):
        client = Client()
        payload = build_extension_zip(
            {"manifest_version": 3, "name": "Cleanish", "version": "1.0", "permissions": ["storage"]},
            {"background.js": "console.log('ok')"},
        )
        response = client.post(
            reverse("scan_console"),
            {"archive": SimpleUploadedFile("cleanish.zip", payload, content_type="application/zip")},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/processing/", response["Location"])
