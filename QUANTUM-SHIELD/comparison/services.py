from django.db.models import Case, Count, IntegerField, Value, When
from django.utils import timezone

from core.models import AlgorithmOperation, AlgorithmProfile, Criticality, CryptographicAsset

from .models import ComparisonScope

PROFILE_FIELDS = (
    "id",
    "name",
    "family",
    "operation",
    "security_level",
    "standard",
    "public_key_size",
    "private_key_size",
    "output_size",
    "supported",
    "deprecated",
)

CRITICALITY_RANK = Case(
    When(criticality=Criticality.CRITICAL, then=Value(0)),
    When(criticality=Criticality.HIGH, then=Value(1)),
    When(criticality=Criticality.MEDIUM, then=Value(2)),
    default=Value(3),
    output_field=IntegerField(),
)


def compare_algorithms(names):
    requested = []
    for value in names or []:
        name = str(value).strip()
        if name:
            requested.append(name)

    profiles = {}
    for profile in AlgorithmProfile.objects.all():
        profiles.setdefault(profile.name.casefold(), profile)

    matched = []
    missing = []
    seen = set()
    for name in requested:
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        profile = profiles.get(key)
        if profile is None:
            missing.append(name)
            continue
        matched.append({field: getattr(profile, field) for field in PROFILE_FIELDS})

    insights = {
        "requested_count": len(requested),
        "matched_count": len(matched),
        "missing_count": len(missing),
        "supported_count": sum(1 for item in matched if item["supported"]),
        "deprecated_count": sum(1 for item in matched if item["deprecated"]),
        "smallest_supported_kem": None,
        "smallest_supported_signature": None,
    }
    for key, operation in (
        ("smallest_supported_kem", AlgorithmOperation.KEM),
        ("smallest_supported_signature", AlgorithmOperation.SIGNATURE),
    ):
        candidates = []
        for profile in AlgorithmProfile.objects.filter(supported=True, operation=operation):
            size = profile.output_size if profile.output_size is not None else profile.public_key_size
            if size is not None:
                candidates.append((size, profile.name, profile.id))
        if candidates:
            size, name, profile_id = min(candidates)
            insights[key] = {"id": profile_id, "name": name, "size": size}

    return {
        "requested": requested,
        "matched": matched,
        "missing": missing,
        "insights": insights,
    }


def compare_inventory(organization=None):
    queryset = CryptographicAsset.objects.all()
    if organization is not None:
        queryset = queryset.filter(organization=organization)

    total = queryset.count()
    asset_rows = list(queryset.only("id", "algorithm", "asset_type", "criticality"))
    vulnerable_ids = {asset.pk for asset in asset_rows if asset.pq_risk}
    vulnerable_by_algorithm = {}
    vulnerable_by_criticality = {}
    for asset in asset_rows:
        if asset.pk not in vulnerable_ids:
            continue
        vulnerable_by_algorithm[asset.algorithm] = vulnerable_by_algorithm.get(asset.algorithm, 0) + 1
        vulnerable_by_criticality[asset.criticality] = vulnerable_by_criticality.get(asset.criticality, 0) + 1

    vulnerable = len(vulnerable_ids)
    protected = total - vulnerable

    by_algorithm = [
        {
            "algorithm": row["algorithm"],
            "count": row["count"],
            "vulnerable": vulnerable_by_algorithm.get(row["algorithm"], 0),
        }
        for row in queryset.values("algorithm").annotate(count=Count("pk")).order_by("algorithm")
    ]
    by_criticality = [
        {
            "criticality": row["criticality"],
            "count": row["count"],
            "vulnerable": vulnerable_by_criticality.get(row["criticality"], 0),
        }
        for row in queryset.values("criticality").annotate(count=Count("pk")).order_by("criticality")
    ]
    high_risk = (
        queryset.select_related("organization")
        .filter(pk__in=vulnerable_ids)
        .annotate(criticality_rank=CRITICALITY_RANK)
        .order_by("criticality_rank", "name")[:20]
    )
    high_risk_assets = [
        {
            "id": asset.pk,
            "name": asset.name,
            "algorithm": asset.algorithm,
            "criticality": asset.criticality,
            "organization_name": asset.organization.name if asset.organization_id else None,
        }
        for asset in high_risk
    ]

    return {
        "total_assets": total,
        "vulnerable_assets": vulnerable,
        "protected_assets": protected,
        "readiness_percent": int(round(protected * 100 / total)) if total else 0,
        "by_algorithm": by_algorithm,
        "by_criticality": by_criticality,
        "high_risk_assets": high_risk_assets,
    }


def build_comparison(name, scope, organization=None, algorithms=None):
    if scope not in ComparisonScope.values:
        raise ValueError("Unknown comparison scope: {0}".format(scope))
    payload = {
        "name": name,
        "scope": scope,
        "generated_at": timezone.now().isoformat(),
    }
    if scope == ComparisonScope.INVENTORY:
        payload["inventory"] = compare_inventory(organization)
    else:
        payload["algorithms"] = compare_algorithms(algorithms)
    return payload
