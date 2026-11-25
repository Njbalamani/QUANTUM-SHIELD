from datetime import date

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
from core.models import AssetStatus, AuditLog, CryptographicAsset, Organization

from .models import MigrationPlan, MigrationTask, PlanStatus, TaskPriority, TaskStatus
from .services import generate_tasks_for_plan, update_task_status


class MigrationServiceTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")

    def make_plan(self, **kwargs):
        defaults = {
            "organization": self.organization,
            "name": "PQ migration",
            "target_algorithm": "KYBER-768",
            "status": PlanStatus.ACTIVE,
        }
        defaults.update(kwargs)
        return MigrationPlan.objects.create(**defaults)

    def test_progress_property_math(self):
        plan = self.make_plan()
        MigrationTask.objects.create(plan=plan, from_algorithm="RSA", to_algorithm="KYBER-768")
        MigrationTask.objects.create(
            plan=plan,
            from_algorithm="ECDSA",
            to_algorithm="KYBER-768",
            status=TaskStatus.IN_PROGRESS,
        )
        MigrationTask.objects.create(
            plan=plan,
            from_algorithm="DH",
            to_algorithm="KYBER-768",
            status=TaskStatus.COMPLETED,
        )
        progress = plan.progress
        self.assertEqual(progress["total"], 3)
        self.assertEqual(progress["completed"], 1)
        self.assertEqual(progress["percent"], 33)
        self.assertEqual(progress["counts"][TaskStatus.PENDING], 1)
        self.assertEqual(progress[TaskStatus.IN_PROGRESS], 1)

    def test_generate_tasks_creates_expected_tasks_and_is_idempotent(self):
        plan = self.make_plan()
        other_org = Organization.objects.create(name="Other", slug="other")
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="rsa service",
            algorithm="RSA-2048",
            criticality="high",
            status=AssetStatus.ACTIVE,
        )
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="ecc service",
            algorithm="ECDSA P-256",
            criticality="critical",
            status=AssetStatus.DEPRECATED,
        )
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="pq service",
            algorithm="Kyber-768",
            status=AssetStatus.ACTIVE,
        )
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="retired service",
            algorithm="RSA-1024",
            status=AssetStatus.RETIRED,
        )
        CryptographicAsset.objects.create(
            organization=other_org,
            name="other service",
            algorithm="RSA-4096",
            status=AssetStatus.ACTIVE,
        )

        self.assertEqual(generate_tasks_for_plan(plan), 2)
        self.assertEqual(generate_tasks_for_plan(plan), 0)
        self.assertEqual(plan.tasks.count(), 2)
        self.assertEqual(
            set(plan.tasks.values_list("priority", flat=True)),
            {TaskPriority.HIGH, TaskPriority.CRITICAL},
        )
        self.assertTrue(AuditLog.objects.filter(action="migration.tasks_generated").exists())

    def test_update_task_status_sets_completed_at_and_audits(self):
        plan = self.make_plan()
        task = MigrationTask.objects.create(plan=plan, from_algorithm="RSA", to_algorithm="KYBER-768")
        before = AuditLog.objects.count()
        update_task_status(task, TaskStatus.COMPLETED, notes="deployed", user=None)
        task.refresh_from_db()
        self.assertEqual(task.status, TaskStatus.COMPLETED)
        self.assertEqual(task.notes, "deployed")
        self.assertIsNotNone(task.completed_at)
        self.assertEqual(AuditLog.objects.count(), before + 1)
        update_task_status(task, TaskStatus.PENDING)
        task.refresh_from_db()
        self.assertIsNone(task.completed_at)


@override_settings(ROOT_URLCONF="migration.urls")
class MigrationApiTests(APITestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")
        self.plan = MigrationPlan.objects.create(
            organization=self.organization,
            name="PQ migration",
            target_algorithm="KYBER-768",
            status=PlanStatus.ACTIVE,
        )
        CryptographicAsset.objects.create(
            organization=self.organization,
            name="rsa service",
            algorithm="RSA-2048",
            criticality="high",
            status=AssetStatus.ACTIVE,
        )
        self.analyst = User.objects.create_user("analyst", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", role=UserRole.VIEWER)

    def test_analyst_can_generate_tasks(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(reverse("migration-plan-generate-tasks", args=[self.plan.pk]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["created"], 1)
        self.assertEqual(self.plan.tasks.count(), 1)

    def test_viewer_cannot_generate_tasks(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(reverse("migration-plan-generate-tasks", args=[self.plan.pk]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(self.plan.tasks.exists())

    def test_update_task_status_endpoint(self):
        task = MigrationTask.objects.create(
            plan=self.plan,
            from_algorithm="RSA",
            to_algorithm="KYBER-768",
            due_date=date(2030, 1, 1),
        )
        self.client.force_authenticate(self.analyst)
        response = self.client.patch(
            reverse("migration-task-detail", args=[task.pk]),
            {"status": TaskStatus.COMPLETED, "notes": "done"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        task.refresh_from_db()
        self.assertIsNotNone(task.completed_at)
        self.assertEqual(task.notes, "done")
