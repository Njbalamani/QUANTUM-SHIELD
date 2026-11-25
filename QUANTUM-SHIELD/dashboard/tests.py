from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import include, path

from accounts.models import User, UserRole
from core.models import Criticality, CryptographicAsset, Organization
from dashboard.context_processors import platform_context
from dashboard.services import get_dashboard_data

urlpatterns = [
    path("", include("dashboard.urls")),
]


class PlatformContextTests(TestCase):
    def test_platform_context_returns_expected_keys(self):
        payload = platform_context(SimpleNamespace(user=None))["platform"]
        self.assertEqual(payload["name"], "QuantumShield")
        self.assertIn("tagline", payload)
        self.assertIn("oqs_available", payload)
        self.assertIn("oqs_version", payload)
        self.assertTrue(payload["navigation"])
        self.assertTrue(all({"label", "url"} <= set(item) for item in payload["navigation"]))
        self.assertIn({"label": "Login", "url": "/login/"}, payload["navigation"])

    def test_platform_context_handles_missing_oqs(self):
        with patch("dashboard.context_processors.get_oqs", return_value=None):
            payload = platform_context(None)["platform"]
        self.assertFalse(payload["oqs_available"])
        self.assertIsNone(payload["oqs_version"])

        with patch("dashboard.context_processors.get_oqs", return_value=object()):
            with patch("dashboard.context_processors.oqs_version", return_value="test-1.0"):
                payload = platform_context(None)["platform"]
        self.assertTrue(payload["oqs_available"])
        self.assertEqual(payload["oqs_version"], "test-1.0")

    def test_dashboard_data_handles_absent_optional_models(self):
        with patch("dashboard.services._optional_model", return_value=None):
            data = get_dashboard_data()
        for key in (
            "organizations",
            "assets",
            "vulnerable_assets",
            "critical_assets",
            "active_plans",
            "pending_migration_tasks",
            "scans",
            "findings",
            "benchmark_runs",
            "reports",
        ):
            self.assertEqual(data["counts"][key], 0)
        self.assertEqual(data["recent_assets"], [])
        self.assertEqual(data["recent_audits"], [])
        self.assertIsNone(data["migration_progress"])


@override_settings(ROOT_URLCONF="dashboard.tests")
class DashboardViewTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")
        self.user = User.objects.create_user("viewer", password="password", role=UserRole.VIEWER)

    def test_landing_page_is_available_to_anonymous_users(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "QuantumShield")
        self.assertContains(response, "post-quantum")

    def test_authenticated_user_is_redirected_from_landing(self):
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_dashboard_redirects_anonymous_users_to_login(self):
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_authenticated_dashboard_renders_with_data(self):
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="Legacy VPN",
            algorithm="RSA-2048",
            criticality=Criticality.CRITICAL,
        )
        self.client.force_login(self.user)
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["counts"]["assets"], 1)
        self.assertEqual(response.context["counts"]["vulnerable_assets"], 1)
        self.assertEqual(response.context["recent_assets"][0]["name"], "Legacy VPN")
        self.assertContains(response, "Quick scan")
        self.assertContains(response, "Quick benchmark")

    def test_health_endpoint_returns_json_ok(self):
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertIn("oqs_available", payload)
        self.assertIn("counts", payload)
        self.assertIn("assets", payload["counts"])

    def test_quick_benchmark_form_creates_run(self):
        self.client.force_login(self.user)
        with patch("benchmarks.services.create_benchmark_run") as create_run:
            response = self.client.post(
                "/dashboard/",
                {"benchmark_submit": "1", "algorithm": "Kyber768", "operation": "kem", "iterations": "4"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        create_run.assert_called_once()
        kwargs = create_run.call_args.kwargs
        self.assertEqual(kwargs["algorithm"], "Kyber768")
        self.assertEqual(kwargs["operation"], "kem")
        self.assertEqual(kwargs["iterations"], 4)
        self.assertEqual(kwargs["requested_by"], self.user)
        self.assertContains(response, "Benchmark completed successfully.")

    def test_quick_scan_form_calls_scanner_service(self):
        self.client.force_login(self.user)
        with patch("scanner.services.scan_text") as scan_text:
            response = self.client.post(
                "/dashboard/",
                {"scan_submit": "1", "name": "Config review", "text": "Uses RSA-2048"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        scan_text.assert_called_once()
        self.assertEqual(scan_text.call_args.args[0], "Uses RSA-2048")
        self.assertEqual(scan_text.call_args.kwargs["name"], "Config review")
        self.assertEqual(scan_text.call_args.kwargs["created_by"], self.user)
        self.assertContains(response, "Scan completed successfully.")
