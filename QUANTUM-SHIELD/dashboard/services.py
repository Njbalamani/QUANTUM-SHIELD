import importlib

from django.apps import apps
from django.db.models import Count

from core.crypto import capability_report
from core.models import AuditLog, Criticality, CryptographicAsset, Organization


def _optional_model(app_label, *names):
    module = None
    try:
        module = importlib.import_module("{0}.models".format(app_label))
    except (ImportError, AttributeError):
        module = None
    for name in names:
        candidate = getattr(module, name, None) if module is not None else None
        if getattr(candidate, "objects", None) is not None:
            return candidate
    for name in names:
        try:
            candidate = apps.get_model(app_label, name)
        except (LookupError, ValueError):
            continue
        if candidate is not None:
            return candidate
    return None


def _has_field(model, name):
    return any(field.name == name for field in model._meta.fields)


def _iso(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _count(model):
    return model.objects.count() if model is not None else 0


def _status_count(model, statuses):
    if model is None or not _has_field(model, "status"):
        return 0
    return model.objects.filter(status__in=statuses).count()


def _migration_progress(plan_model, task_model):
    if plan_model is None:
        return None
    total_plans = plan_model.objects.count()
    if not total_plans:
        return None
    completed_plans = _status_count(plan_model, {"completed", "complete", "done"})
    completed_tasks = _status_count(task_model, {"completed", "complete", "done"})
    total_tasks = _count(task_model)
    if total_tasks:
        total = total_tasks
        completed = completed_tasks
    else:
        total = total_plans
        completed = completed_plans
    percent = int(round(completed * 100 / total)) if total else 0
    return {
        "total": total,
        "completed": completed,
        "percent": percent,
        "plans": total_plans,
        "plans_completed": completed_plans,
        "tasks": total_tasks,
        "tasks_completed": completed_tasks,
    }


def get_dashboard_data(user=None):
    assets = CryptographicAsset.objects.all()
    asset_rows = list(assets.only("id", "name", "algorithm", "criticality", "asset_type"))
    vulnerable_ids = {asset.pk for asset in asset_rows if asset.pq_risk}

    scan_model = _optional_model("scanner", "Scan")
    finding_model = _optional_model("scanner", "ScanFinding", "Finding")
    plan_model = _optional_model("migration", "MigrationPlan", "Plan")
    task_model = _optional_model("migration", "MigrationTask", "Task")
    benchmark_model = _optional_model("benchmarks", "BenchmarkRun")
    report_model = _optional_model("reports", "Report")

    task_queryset = task_model.objects.all() if task_model is not None else None
    if task_queryset is not None and _has_field(task_model, "status"):
        pending_tasks = task_queryset.exclude(status__in={"completed", "skipped"}).count()
    else:
        pending_tasks = _count(task_model)

    counts = {
        "organizations": Organization.objects.count(),
        "assets": len(asset_rows),
        "vulnerable_assets": len(vulnerable_ids),
        "critical_assets": assets.filter(criticality=Criticality.CRITICAL).count(),
        "active_plans": _status_count(plan_model, {"active", "in_progress", "in-progress"}),
        "pending_migration_tasks": pending_tasks,
        "scans": _count(scan_model),
        "findings": _count(finding_model),
        "benchmark_runs": _count(benchmark_model),
        "reports": _count(report_model),
    }

    recent_rows = assets.order_by("-created_at").only(
        "id", "name", "algorithm", "criticality", "asset_type"
    )[:8]
    recent_assets = [
        {
            "id": asset.pk,
            "name": asset.name,
            "algorithm": asset.algorithm,
            "criticality": asset.criticality,
            "pq_risk": asset.pq_risk,
        }
        for asset in recent_rows
    ]

    recent_audits = []
    for row in AuditLog.objects.values("action", "created_at", "user__username").order_by("-created_at")[:10]:
        recent_audits.append(
            {
                "action": row["action"],
                "created_at": _iso(row["created_at"]),
                "username": row["user__username"] or "",
            }
        )

    risk_rows = (
        assets.filter(pk__in=vulnerable_ids)
        .values("algorithm")
        .annotate(count=Count("id"))
        .order_by("-count", "algorithm")[:8]
    )
    risk_by_algorithm = [{"algorithm": row["algorithm"], "count": row["count"]} for row in risk_rows]

    try:
        oqs_report = capability_report()
    except Exception:
        oqs_report = {
            "oqs_available": False,
            "oqs_version": None,
            "enabled_kems": [],
            "enabled_signatures": [],
            "warning": "Capability report unavailable.",
        }

    data = dict(counts)
    data.update(
        {
            "counts": counts,
            "recent_assets": recent_assets,
            "recent_audits": recent_audits,
            "risk_by_algorithm": risk_by_algorithm,
            "migration_progress": _migration_progress(plan_model, task_model),
            "oqs": oqs_report,
        }
    )
    return data
