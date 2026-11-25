from django.utils import timezone

from core.audit import record_audit
from core.models import AssetStatus, Criticality, CryptographicAsset

from .models import MigrationTask, TaskPriority, TaskStatus

PRIORITY_BY_CRITICALITY = {
    Criticality.LOW: TaskPriority.LOW,
    Criticality.MEDIUM: TaskPriority.MEDIUM,
    Criticality.HIGH: TaskPriority.HIGH,
    Criticality.CRITICAL: TaskPriority.CRITICAL,
}


def generate_tasks_for_plan(plan, *, request=None):
    assets = CryptographicAsset.objects.select_related("organization").filter(
        status__in={AssetStatus.ACTIVE, AssetStatus.DEPRECATED}
    )
    if plan.organization_id is not None:
        assets = assets.filter(organization=plan.organization)

    existing = set(
        MigrationTask.objects.filter(plan=plan, asset__isnull=False)
        .exclude(status=TaskStatus.COMPLETED)
        .values_list("asset_id", flat=True)
    )
    target = plan.target_algorithm.strip().lower()
    created = 0
    for asset in assets:
        if asset.pk in existing or not asset.pq_risk:
            continue
        if asset.algorithm.strip().lower() == target:
            continue
        MigrationTask.objects.create(
            plan=plan,
            asset=asset,
            from_algorithm=asset.algorithm,
            to_algorithm=plan.target_algorithm,
            status=TaskStatus.PENDING,
            priority=PRIORITY_BY_CRITICALITY.get(asset.criticality, TaskPriority.MEDIUM),
        )
        created += 1

    record_audit(
        request,
        "migration.tasks_generated",
        obj=plan,
        details={"created": created},
    )
    return created


def update_task_status(task, status, *, notes=None, request=None, user=None):
    if status not in TaskStatus.values:
        raise ValueError(f"Unknown task status: {status}")
    task.status = status
    if notes:
        task.notes = f"{task.notes}\n{notes}".strip() if task.notes else notes
    task.completed_at = timezone.now() if status == TaskStatus.COMPLETED else None
    task.save()
    record_audit(
        request,
        "migration.task.status",
        obj=task,
        details={"status": status, "notes": notes or ""},
        user=user,
    )
    return task


def plan_summary(plan):
    tasks = plan.tasks.select_related("asset")
    by_status = {status: 0 for status in TaskStatus.values}
    by_priority = {priority: 0 for priority in TaskPriority.values}
    all_tasks = list(tasks)
    for task in all_tasks:
        by_status[task.status] = by_status.get(task.status, 0) + 1
        by_priority[task.priority] = by_priority.get(task.priority, 0) + 1

    upcoming = []
    for task in sorted(
        (task for task in all_tasks if task.due_date is not None),
        key=lambda task: (task.due_date, task.pk),
    )[:10]:
        upcoming.append(
            {
                "id": task.pk,
                "from_algorithm": task.from_algorithm,
                "to_algorithm": task.to_algorithm,
                "asset_name": task.asset.name if task.asset_id else None,
                "status": task.status,
                "priority": task.priority,
                "due_date": task.due_date.isoformat(),
            }
        )

    return {
        "id": plan.pk,
        "name": plan.name,
        "status": plan.status,
        "target_algorithm": plan.target_algorithm,
        "owner": plan.owner,
        "progress": plan.progress,
        "by_status": by_status,
        "by_priority": by_priority,
        "task_counts_by_status": by_status,
        "task_counts_by_priority": by_priority,
        "upcoming_due_tasks": upcoming,
        "upcoming": upcoming,
    }
