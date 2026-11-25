from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
from comparison.models import ComparisonScope
from comparison.services import build_comparison, compare_algorithms, compare_inventory
from core.models import (
    AlgorithmFamily,
    AlgorithmOperation,
    AlgorithmProfile,
    AssetStatus,
    AuditLog,
    Criticality,
    CryptographicAsset,
    Organization,
)


class InventoryComparisonServiceTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")

    def test_inventory_comparison_identifies_vulnerable_and_protected_assets(self):
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="Legacy VPN",
            algorithm="RSA-2048",
            criticality=Criticality.CRITICAL,
            status=AssetStatus.ACTIVE,
        )
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="Modern VPN",
            algorithm="Kyber768",
            criticality=Criticality.HIGH,
            status=AssetStatus.ACTIVE,
        )
        result = compare_inventory(self.organization)
        self.assertEqual(result["total_assets"], 2)
        self.assertEqual(result["vulnerable_assets"], 1)
        self.assertEqual(result["protected_assets"], 1)
        self.assertEqual(result["readiness_percent"], 50)
        self.assertEqual(result["high_risk_assets"][0]["name"], "Legacy VPN")
        self.assertEqual(result["high_risk_assets"][0]["organization_name"], "Acme")
        self.assertTrue(any(row["algorithm"] == "RSA-2048" and row["vulnerable"] == 1 for row in result["by_algorithm"]))

    def test_inventory_comparison_empty_scope(self):
        result = compare_inventory(self.organization)
        self.assertEqual(result["total_assets"], 0)
        self.assertEqual(result["readiness_percent"], 0)
        self.assertEqual(result["high_risk_assets"], [])


class AlgorithmComparisonServiceTests(TestCase):
    def test_algorithm_comparison_matches_case_insensitively(self):
        AlgorithmProfile.objects.create(
            name="Kyber768",
            family=AlgorithmFamily.POST_QUANTUM,
            operation=AlgorithmOperation.KEM,
            supported=True,
            public_key_size=1184,
            output_size=1088,
        )
        AlgorithmProfile.objects.create(
            name="Dilithium3",
            family=AlgorithmFamily.POST_QUANTUM,
            operation=AlgorithmOperation.SIGNATURE,
            supported=True,
            deprecated=True,
            public_key_size=1952,
            output_size=3293,
        )
        result = compare_algorithms(["kyber768", "DILITHIUM3", "missing"])
        self.assertEqual([item["name"] for item in result["matched"]], ["Kyber768", "Dilithium3"])
        self.assertEqual(result["missing"], ["missing"])
        self.assertEqual(result["insights"]["supported_count"], 2)
        self.assertEqual(result["insights"]["deprecated_count"], 1)
        self.assertEqual(result["insights"]["smallest_supported_kem"]["name"], "Kyber768")

    def test_build_comparison_rejects_unknown_scope(self):
        with self.assertRaises(ValueError):
            build_comparison("Invalid", "unknown")


@override_settings(ROOT_URLCONF="comparison.urls")
class ComparisonApiTests(APITestCase):
    def setUp(self):
        self.analyst = User.objects.create_user(
            "analyst", password="password", role=UserRole.ANALYST
        )
        self.viewer = User.objects.create_user(
            "viewer", password="password", role=UserRole.VIEWER
        )
        self.organization = Organization.objects.create(name="Acme", slug="acme")

    def test_analyst_can_create_and_preview_comparison(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("comparison-run-list"),
            {"name": "Quarterly review", "scope": ComparisonScope.INVENTORY, "organization": self.organization.id},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["requested_by_username"], "analyst")
        self.assertIn("inventory", response.data["summary"])
        self.assertTrue(AuditLog.objects.filter(action="comparison.create").exists())

        preview = self.client.post(
            reverse("comparison-run-preview"),
            {"name": "Preview", "scope": ComparisonScope.ALGORITHMS, "algorithms": ["Kyber768"]},
            format="json",
        )
        self.assertEqual(preview.status_code, status.HTTP_200_OK)
        self.assertIn("algorithms", preview.data)
        self.assertFalse(preview.data["algorithms"]["matched"])

    def test_viewer_cannot_create_comparison(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("comparison-run-list"),
            {"name": "Blocked", "scope": ComparisonScope.INVENTORY},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_available_algorithms_requires_algorithm_list(self):
        AlgorithmProfile.objects.create(
            name="Kyber768",
            family=AlgorithmFamily.POST_QUANTUM,
            operation=AlgorithmOperation.KEM,
            supported=True,
        )
        self.client.force_authenticate(self.viewer)
        response = self.client.get(reverse("comparison-run-available-algorithms"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["name"], "Kyber768")

    def test_algorithms_scope_requires_at_least_one_algorithm(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("comparison-run-list"),
            {"name": "Invalid", "scope": ComparisonScope.ALGORITHMS},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
