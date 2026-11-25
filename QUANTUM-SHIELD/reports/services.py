import csv
import importlib
import io
import json

from django.apps import apps
from django.db.models import Avg, Count, Q
from django.utils import timezone

from core.audit import record_audit
from core.models import AssetStatus, AuditLog, CryptographicAsset, Organization

from .models import Report, ReportFormat, ReportKind, ReportStatus


def _field_names(model):
    return {field.name for field in model._meta.fields}


def _iso(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _optional_models(app_label, *names):
    result = []
    for name in names:
        model = None
        try:
            module = importlib.import_module("{0}.models".format(app_label))
            candidate = getattr(module, name, None)
            if hasattr(candidate, "objects"):
                model = candidate
        except (ImportError, AttributeError):
            model = None
        if model is None:
            try:
                model = apps.get_model(app_label, name)
            except (LookupError, ValueError):
                model = None
        result.append(model)
    return result


def _app_models(app_label, keywords):
    try:
        config = apps.get_app_config(app_label)
    except (LookupError, ValueError):
        return []
    return [
        model
        for model in config.get_models()
        if any(keyword in model.__name__.lower() for keyword in keywords)
    ]


def _scoped(source, organization):
    queryset = source.objects.all() if hasattr(source, "objects") else source.all()
    if organization is not None and "organization" in _field_names(queryset.model):
        queryset = queryset.filter(organization=organization)
    return queryset


def _latest_rows(queryset, fields, ordering="created_at", limit=10):
    available = _field_names(queryset.model)
    names = [name for name in fields if name in available] or ["pk"]
    if ordering in available:
        queryset = queryset.order_by("-" + ordering)
    if names:
        queryset = queryset.values(*names)
    return [{key: _iso(value) for key, value in row.items()} for row in queryset[:limit]]


def _status_count(queryset, statuses):
    if "status" in _field_names(queryset.model):
        return queryset.filter(status__in=statuses).count()
    return 0


def _average(queryset, field):
    if field not in _field_names(queryset.model):
        return None
    return queryset.aggregate(value=Avg(field))["value"]


def _finding_key(finding_model, scan_model):
    for field in finding_model._meta.fields:
        remote = getattr(field, "remote_field", None)
        if remote is not None and getattr(remote, "model", None) is scan_model:
            return field.name
    return None


def _overview_section():
    migration_models = _optional_models("migration", "MigrationPlan", "Plan")
    migration_plan = next((model for model in migration_models if model is not None), None)
    benchmark_models = _optional_models("benchmarks", "BenchmarkRun", "Benchmark", "BenchmarkResult")
    benchmark_run = next((model for model in benchmark_models if model is not None), None)
    if benchmark_run is None:
        benchmark_run = next(iter(_app_models("benchmarks", ("benchmark",))), None)

    vulnerability_rows = CryptographicAsset.objects.only("id", "algorithm", "asset_type")
    recent_actions = [
        {"id": row["id"], "action": row["action"], "created_at": _iso(row["created_at"])}
        for row in AuditLog.objects.values("id", "action", "created_at").order_by("-created_at")[:10]
    ]
    return {
        "organizations": Organization.objects.count(),
        "assets": CryptographicAsset.objects.count(),
        "vulnerable_assets": sum(1 for asset in vulnerability_rows if asset.pq_risk),
        "active_migration_plans": (
            _status_count(_scoped(migration_plan, None), {"active", "in_progress", "in-progress"})
            if migration_plan is not None
            else 0
        ),
        "completed_benchmark_runs": (
            _status_count(_scoped(benchmark_run, None), {"completed", "complete", "ready", "success"})
            if benchmark_run is not None
            else 0
        ),
        "ready_reports": Report.objects.filter(status=ReportStatus.READY).count(),
        "recent_audit_actions": recent_actions,
    }


def _inventory_section(organization):
    queryset = _scoped(CryptographicAsset.objects.all(), organization)
    counts = queryset.aggregate(
        total=Count("pk"),
        active=Count("pk", filter=Q(status=AssetStatus.ACTIVE)),
        retired=Count("pk", filter=Q(status=AssetStatus.RETIRED)),
    )
    vulnerability_rows = list(queryset.only("id", "algorithm", "asset_type"))
    by_criticality = [
        {"criticality": row["criticality"], "count": row["count"]}
        for row in queryset.values("criticality").annotate(count=Count("pk")).order_by("criticality")
    ]
    by_algorithm = [
        {"algorithm": row["algorithm"], "count": row["count"]}
        for row in queryset.values("algorithm").annotate(count=Count("pk")).order_by("algorithm")
    ]
    assets = []
    for asset in queryset.select_related("organization")[:50]:
        assets.append(
            {
                "id": asset.pk,
                "name": asset.name,
                "organization": asset.organization.name if asset.organization_id else None,
                "algorithm": asset.algorithm,
                "criticality": asset.criticality,
                "status": asset.status,
                "pq_risk": asset.pq_risk,
            }
        )
    return {
        "total": counts["total"],
        "active": counts["active"],
        "retired": counts["retired"],
        "vulnerable": sum(1 for asset in vulnerability_rows if asset.pq_risk),
        "by_criticality": by_criticality,
        "by_algorithm": by_algorithm,
        "assets": assets,
    }


def _scanner_section(organization):
    scan_models = _optional_models("scanner", "Scan")
    finding_models = _optional_models("scanner", "ScanFinding", "Finding")
    scan_model = next((model for model in scan_models if model is not None), None)
    finding_model = next((model for model in finding_models if model is not None), None)

    scans = []
    total_scans = 0
    total_findings = 0
    if scan_model is not None:
        scan_queryset = _scoped(scan_model, organization)
        total_scans = scan_queryset.count()
        for scan in _latest_rows(scan_queryset, ("id", "name", "status", "created_at"), limit=10):
            finding_count = 0
            if finding_model is not None:
                key = _finding_key(finding_model, scan_model)
                if key:
                    finding_queryset = _scoped(finding_model, organization)
                    scan_id = scan.get("id", scan.get("pk"))
                    finding_count = finding_queryset.filter(**{"{0}_id".format(key): scan_id}).count()
            scan["finding_count"] = finding_count
            scans.append(scan)
    if finding_model is not None:
        total_findings = _scoped(finding_model, organization).count()
    return {
        "scans": scans,
        "total_scans": total_scans,
        "total_findings": total_findings,
    }


def _benchmark_section(organization):
    models = _optional_models("benchmarks", "BenchmarkRun", "Benchmark", "BenchmarkResult")
    model = next((item for item in models if item is not None), None)
    if model is None:
        model = next(iter(_app_models("benchmarks", ("benchmark",))), None)
    if model is None:
        return {
            "runs": [],
            "total_runs": 0,
            "completed_runs": 0,
            "failed_runs": 0,
            "average_iterations": None,
        }
    queryset = _scoped(model, organization)
    runs = _latest_rows(queryset, ("id", "algorithm", "operation", "status", "iterations", "created_at"), limit=10)
    return {
        "runs": runs,
        "total_runs": queryset.count(),
        "completed_runs": _status_count(queryset, {"completed", "complete", "ready", "success"}),
        "failed_runs": _status_count(queryset, {"failed", "error"}),
        "average_iterations": _average(queryset, "iterations"),
    }


def _migration_section(organization):
    plan_models = _optional_models("migration", "MigrationPlan", "Plan")
    plan_model = next((model for model in plan_models if model is not None), None)
    if plan_model is None:
        plan_model = next(iter(_app_models("migration", ("plan",))), None)
    plans = []
    if plan_model is not None:
        queryset = _scoped(plan_model, organization)
        if "created_at" in _field_names(plan_model):
            queryset = queryset.order_by("-created_at")
        for plan in queryset[:20]:
            plans.append(
                {
                    "id": plan.pk,
                    "name": getattr(plan, "name", str(plan)),
                    "status": getattr(plan, "status", None),
                    "target_algorithm": getattr(plan, "target_algorithm", None),
                    "progress": getattr(plan, "progress", None),
                }
            )

    task_model = None
    for candidate in _optional_models("migration", "MigrationTask", "Task"):
        if candidate is not None:
            task_model = candidate
            break
    if task_model is None:
        try:
            task_model = next(
                (model for model in apps.get_app_config("migration").get_models() if "task" in model.__name__.lower()),
                None,
            )
        except (LookupError, ValueError):
            task_model = None

    task_totals = {"total": 0, "completed": 0}
    if task_model is not None:
        queryset = _scoped(task_model, organization)
        task_totals["total"] = queryset.count()
        available = _field_names(task_model)
        if "status" in available:
            task_totals["completed"] = queryset.filter(
                status__in={"completed", "complete", "done", "ready"}
            ).count()
        elif "completed" in available:
            task_totals["completed"] = queryset.filter(completed=True).count()

    return {
        "plans": plans,
        "tasks_total": task_totals["total"],
        "tasks_completed": task_totals["completed"],
        "task_totals": task_totals,
    }


def _comparison_section(organization):
    try:
        from comparison.models import ComparisonRun
    except (ImportError, AttributeError):
        return {"runs": []}
    queryset = ComparisonRun.objects.all()
    if organization is not None:
        queryset = queryset.filter(organization=organization)
    if "created_at" in _field_names(ComparisonRun):
        queryset = queryset.order_by("-created_at")
    runs = [
        {
            "id": run.pk,
            "name": run.name,
            "scope": run.scope,
            "created_at": _iso(run.created_at),
            "summary": run.summary,
        }
        for run in queryset[:20]
    ]
    return {"runs": runs}


def build_report(kind, organization=None, filters=None):
    if kind not in ReportKind.values:
        raise ValueError("Unknown report kind: {0}".format(kind))

    label = ReportKind(kind).label
    title = "{0} report".format(label)
    if organization is not None:
        title = "{0} - {1}".format(title, organization.name)

    sections = {}
    if kind == ReportKind.OVERVIEW:
        sections[kind] = _overview_section()
    elif kind == ReportKind.INVENTORY:
        sections[kind] = _inventory_section(organization)
    elif kind == ReportKind.SCANNER:
        sections[kind] = _scanner_section(organization)
    elif kind == ReportKind.BENCHMARK:
        sections[kind] = _benchmark_section(organization)
    elif kind == ReportKind.MIGRATION:
        sections[kind] = _migration_section(organization)
    else:
        sections[kind] = _comparison_section(organization)

    return {
        "title": title,
        "kind": kind,
        "generated_at": timezone.now().isoformat(),
        "organization": {"id": organization.pk, "name": organization.name} if organization is not None else None,
        "filters": filters or {},
        "summary": {key: value for key, value in sections[kind].items() if not isinstance(value, (list, dict))},
        "sections": sections,
    }


def _stringify(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def render_report(report):
    payload = report.summary.get("payload") if isinstance(report.summary, dict) else None
    if not isinstance(payload, dict):
        payload = build_report(report.kind, organization=report.organization, filters=report.filters)

    if report.format != ReportFormat.CSV:
        return json.dumps(payload, indent=2, sort_keys=True, default=str)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "key", "value"])
    for key, value in (payload.get("summary") or {}).items():
        writer.writerow(["summary", key, _stringify(value)])
    for section_name, section in (payload.get("sections") or {}).items():
        if isinstance(section, dict):
            for key, value in section.items():
                writer.writerow([section_name, key, _stringify(value)])
        else:
            writer.writerow([section_name, "", _stringify(section)])
    return output.getvalue()


def generate_report(*, title, kind, format=ReportFormat.JSON, organization=None, filters=None, generated_by=None, request=None):
    filters = filters or {}
    report = Report.objects.create(
        title=title,
        kind=kind,
        format=format,
        organization=organization,
        filters=filters,
        generated_by=generated_by,
        status=ReportStatus.PENDING,
    )
    try:
        payload = build_report(kind, organization=organization, filters=filters)
        report.summary = {
            "title": payload["title"],
            "kind": payload["kind"],
            "generated_at": payload["generated_at"],
            "organization": payload["organization"],
            **payload["summary"],
            "payload": payload,
        }
        report.content = render_report(report)
        report.status = ReportStatus.READY
        report.completed_at = timezone.now()
        report.save()
        record_audit(
            request,
            "report.generate",
            obj=report,
            details={"title": title, "kind": kind, "format": report.format, "status": report.status},
            user=generated_by,
        )
        return report
    except Exception as exc:
        report.status = ReportStatus.FAILED
        report.error = str(exc)
        report.completed_at = timezone.now()
        report.save()
        record_audit(
            request,
            "report.failed",
            obj=report,
            details={"title": title, "kind": kind, "error": str(exc)},
            user=generated_by,
        )
        raise
