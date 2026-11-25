from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
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


class InventoryApiTests(APITestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")
        self.other_organization = Organization.objects.create(name="Globex", slug="globex")
        self.admin = User.objects.create_superuser("admin", password="AdminPassword123!")
        self.analyst = User.objects.create_user("analyst", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", role=UserRole.VIEWER)
        self.asset = CryptographicAsset.objects.create(
            organization=self.organization,
            name="Legacy VPN",
            algorithm="RSA-2048",
            criticality=Criticality.HIGH,
            status=AssetStatus.ACTIVE,
        )
        self.other_asset = CryptographicAsset.objects.create(
            organization=self.other_organization,
            name="Archive",
            algorithm="AES-256",
            criticality=Criticality.LOW,
            status=AssetStatus.ACTIVE,
        )

    def test_viewer_can_list_assets_with_pq_risk(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.get(reverse("asset-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["results"]
        self.assertEqual(len(results), 2)
        by_id = {item["id"]: item for item in results}
        self.assertTrue(by_id[self.asset.pk]["pq_risk"])
        self.assertFalse(by_id[self.other_asset.pk]["pq_risk"])

    def test_analyst_can_create_asset_with_creator_and_audit(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("asset-list"),
            {
                "organization": self.organization.pk,
                "name": "Payment Gateway",
                "algorithm": "ECDSA P-256",
                "criticality": Criticality.CRITICAL,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        asset = CryptographicAsset.objects.get(pk=response.data["id"])
        self.assertEqual(asset.created_by, self.analyst)
        audit = AuditLog.objects.get(action="asset.create")
        self.assertEqual(audit.user, self.analyst)
        self.assertEqual(audit.object_type, CryptographicAsset._meta.label)
        self.assertEqual(audit.object_id, str(asset.pk))
        self.assertIn("fields", audit.details)

    def test_viewer_cannot_create_asset(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("asset-list"),
            {
                "organization": self.organization.pk,
                "name": "Blocked Asset",
                "algorithm": "RSA-2048",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(CryptographicAsset.objects.filter(name="Blocked Asset").exists())

    def test_mark_retired_changes_status_and_writes_audit(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(reverse("asset-mark-retired", args=[self.asset.pk]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.asset.refresh_from_db()
        self.assertEqual(self.asset.status, AssetStatus.RETIRED)
        self.assertEqual(response.data["status"], AssetStatus.RETIRED)
        audit = AuditLog.objects.get(action="asset.mark_retired")
        self.assertEqual(audit.user, self.analyst)
        self.assertEqual(audit.object_id, str(self.asset.pk))
        self.assertEqual(audit.details["previous_status"], AssetStatus.ACTIVE)
        self.assertEqual(audit.details["status"], AssetStatus.RETIRED)

    def test_manual_filters_narrow_assets_by_slug_and_criticality(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.get(reverse("asset-list"), {"organization": self.organization.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([item["id"] for item in response.data["results"]], [self.asset.pk])

        response = self.client.get(reverse("asset-list"), {"criticality": Criticality.LOW})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([item["id"] for item in response.data["results"]], [self.other_asset.pk])

    def test_admin_can_create_and_update_algorithm_profile(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            reverse("algorithm-profile-list"),
            {
                "name": "Kyber768",
                "family": AlgorithmFamily.POST_QUANTUM,
                "operation": AlgorithmOperation.KEM,
                "security_level": "3",
                "supported": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        profile = AlgorithmProfile.objects.get(pk=response.data["id"])
        detail_url = reverse("algorithm-profile-detail", args=[profile.pk])
        update = self.client.patch(
            detail_url,
            {"notes": "Approved for evaluation", "deprecated": False},
            format="json",
        )
        self.assertEqual(update.status_code, status.HTTP_200_OK)
        profile.refresh_from_db()
        self.assertEqual(profile.notes, "Approved for evaluation")
        actions = set(AuditLog.objects.values_list("action", flat=True))
        self.assertIn("algorithm_profile.create", actions)
        self.assertIn("algorithm_profile.update", actions)

    def test_analyst_cannot_create_algorithm_profile(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            reverse("algorithm-profile-list"),
            {
                "name": "Dilithium3",
                "family": AlgorithmFamily.POST_QUANTUM,
                "operation": AlgorithmOperation.SIGNATURE,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(AlgorithmProfile.objects.filter(name="Dilithium3").exists())
