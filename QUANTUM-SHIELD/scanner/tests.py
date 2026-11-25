from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole

from .models import ScanFinding, ScanPattern, ScanSource
from .services import ensure_default_patterns, finding_line_column, scan_text, scan_upload


class ScannerServiceTests(TestCase):
    def test_ensure_default_patterns_is_idempotent(self):
        first = ensure_default_patterns()
        second = ensure_default_patterns()
        self.assertGreaterEqual(first, 10)
        self.assertEqual(second, 0)
        self.assertEqual(ScanPattern.objects.count(), first)

    def test_scan_text_finds_rsa_and_sha1_and_builds_summary(self):
        ensure_default_patterns()
        text = "service RSA-2048 uses SHA-1 and legacy MD5\nsecond line\n"
        scan = scan_text(text, name="QA scan")
        self.assertEqual(scan.status, "completed")
        self.assertEqual(len(scan.content_hash), 64)
        self.assertEqual(scan.summary["total"], scan.findings.count())
        self.assertGreaterEqual(scan.summary["by_severity"].get("high", 0), 2)
        self.assertGreaterEqual(scan.summary["by_category"].get("hash", 0), 2)
        matched = list(scan.findings.values_list("matched_text", flat=True))
        self.assertTrue(any("RSA" in value for value in matched))
        self.assertTrue(any("SHA-1" in value for value in matched))

    def test_finding_line_column(self):
        text = "alpha\nbeta\ngamma"
        self.assertEqual(finding_line_column(text, 0), (1, 1))
        self.assertEqual(finding_line_column(text, 6), (2, 1))
        self.assertEqual(finding_line_column(text, 9), (2, 4))
        self.assertEqual(finding_line_column(text, 11), (3, 1))
        self.assertEqual(finding_line_column(text, 12), (3, 2))

    @override_settings(QS_MAX_UPLOAD_MB=1)
    def test_scan_text_rejects_oversized_content(self):
        with self.assertRaises(ValueError):
            scan_text("a" * (1024 * 1024 + 1))

    def test_scan_upload_sets_file_location_and_source(self):
        ensure_default_patterns()
        upload = SimpleUploadedFile("config.txt", b"uses RC4 and BLOWFISH", content_type="text/plain")
        scan = scan_upload(upload)
        self.assertEqual(scan.source, ScanSource.FILE)
        self.assertEqual(scan.location, "config.txt")
        self.assertTrue(scan.findings.exists())


@override_settings(ROOT_URLCONF="scanner.urls")
class ScannerApiTests(APITestCase):
    def setUp(self):
        self.analyst = User.objects.create_user("analyst", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", role=UserRole.VIEWER)
        ensure_default_patterns()

    def test_analyst_can_create_scan(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("scan-list"),
            {"name": "API scan", "text": "TLS 1.0 with RSA-2048"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "API scan")
        self.assertEqual(response.data["finding_count"], ScanFinding.objects.count())
        self.assertEqual(len(response.data["content_hash"]), 64)

    def test_viewer_cannot_create_scan(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("scan-list"),
            {"text": "RSA-2048"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(ScanFinding.objects.exists())
