import json

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
from core.audit import record_audit
from core.models import AssetStatus, Criticality, CryptographicAsset, Organization
from reports.models import ReportFormat, ReportKind, ReportStatus
from reports.services import build_report, generate_report


class BuildOverviewReportTests(TestCase):
    def test_overview_report_counts_data_and_recent_audit_actions(self):
        organization = Organization.objects.create(name="Acme", slug="acme")
        CryptographicAsset.objects.create(
            organization=organization,
            name="Legacy VPN",
            algorithm="RSA-2048",
            criticality=Criticality.CRITICAL,
            status=AssetStatus.ACTIVE,
        )
        CryptographicAsset.objects.create(
            organization=organization,
            name="Modern VPN",
            algorithm="Kyber768",
            criticality=Criticality.HIGH,
            status=AssetStatus.ACTIVE,
        )
        ready_report = generate_report(
            title="Existing report", kind=ReportKind.INVENTORY, generated_by=None
        )
        record_audit(action="test.action", details={"source": "test"})

        payload = build_report(ReportKind.OVERVIEW)
        section = payload["sections"][ReportKind.OVERVIEW]
        self.assertEqual(payload["kind"], ReportKind.OVERVIEW)
        self.assertEqual(section["organizations"], 1)
        self.assertEqual(section["assets"], 2)
        self.assertEqual(section["vulnerable_assets"], 1)
        self.assertEqual(section["ready_reports"], 1)
        self.assertEqual(ready_report.status, ReportStatus.READY)
        self.assertIn("test.action", [item["action"] for item in section["recent_audit_actions"]])

    def test_unknown_kind_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_report("unknown")


class GenerateReportServiceTests(TestCase):
    def test_generate_report_creates_ready_row_with_content_and_audit(self):
        user = User.objects.create_user("analyst", password="password", role=UserRole.ANALYST)
        report = generate_report(
            title="Inventory snapshot",
            kind=ReportKind.INVENTORY,
            generated_by=user,
        )
        report.refresh_from_db()
        self.assertEqual(report.status, ReportStatus.READY)
        self.assertIsNotNone(report.completed_at)
        self.assertEqual(report.generated_by, user)
        self.assertIn("payload", report.summary)
        payload = json.loads(report.content)
        self.assertEqual(report.title, "Inventory snapshot")
        self.assertEqual(payload["kind"], ReportKind.INVENTORY)
        self.assertEqual(payload["title"], ReportKind.INVENTORY.label + " report")


@override_settings(ROOT_URLCONF="reports.urls")
class ReportApiTests(APITestCase):
    def setUp(self):
        self.analyst = User.objects.create_user(
            "analyst", password="password", role=UserRole.ANALYST
        )
        self.viewer = User.objects.create_user(
            "viewer", password="password", role=UserRole.VIEWER
        )
        self.organization = Organization.objects.create(name="Acme", slug="acme")

    def test_analyst_can_create_and_preview_report(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("report-list"),
            {
                "title": "Overview",
                "kind": ReportKind.OVERVIEW,
                "organization": self.organization.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["status"], ReportStatus.READY)
        self.assertEqual(response.data["generated_by_username"], "analyst")
        self.assertEqual(json.loads(response.data["content"])["kind"], ReportKind.OVERVIEW)

        preview = self.client.post(
            reverse("report-preview"),
            {"title": "Preview", "kind": ReportKind.INVENTORY, "filters": {"criticality": "high"}},
            format="json",
        )
        self.assertEqual(preview.status_code, status.HTTP_200_OK)
        self.assertEqual(preview.data["filters"], {"criticality": "high"})

    def test_viewer_cannot_create_report(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("report-list"),
            {"title": "Blocked", "kind": ReportKind.OVERVIEW},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_download_returns_csv_content_type(self):
        report = generate_report(
            title="CSV Export",
            kind=ReportKind.OVERVIEW,
            format=ReportFormat.CSV,
            generated_by=self.analyst,
        )
        self.client.force_authenticate(self.viewer)
        response = self.client.get(reverse("report-download", args=[report.pk]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("text/csv", response["Content-Type"])
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertIn("section,key,value", response.content.decode("utf-8"))
