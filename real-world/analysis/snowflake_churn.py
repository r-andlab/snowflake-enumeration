"""Helpers for loading Snowflake measurement data and analyzing churn."""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from statistics import mean, median
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set


UNKNOWN_ASN_VALUES = {"ASN not found", "ASNNOTFOUND", "", "None", "nan"}
UNKNOWN_COUNTRY_VALUES = {"Unknown", "", "None", "nan"}


@dataclass(frozen=True)
class DatasetPaths:
    """Canonical file locations for each Snowflake proxy pool."""

    raw: Path
    enriched: Path


DEFAULT_DATASETS: Mapping[str, DatasetPaths] = {
    "restricted": DatasetPaths(
        raw=Path("restricted.csv"),
        enriched=Path("restricted_with_country_with_rank.csv"),
    ),
    "unrestricted": DatasetPaths(
        raw=Path("unrestricted.csv"),
        enriched=Path("unrestricted_with_country_with_rank.csv"),
    ),
}


def _parse_date(value: str) -> date:
    if "T" in value:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    return datetime.strptime(value, "%Y-%m-%d").date()


def _normalize_asn(value: str) -> Optional[str]:
    asn = str(value).strip()
    if asn in UNKNOWN_ASN_VALUES:
        return None
    if asn.upper().startswith("AS"):
        asn = asn[2:].strip()
    return asn or None


def _normalize_country(value: str) -> Optional[str]:
    country = str(value).strip()
    if country in UNKNOWN_COUNTRY_VALUES:
        return None
    return country or None


def load_enriched_rows(csv_path: Path | str) -> List[dict]:
    """Load an enriched measurement CSV with normalized core fields."""
    path = Path(csv_path)
    rows: List[dict] = []
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(
                {
                    "date": _parse_date(row["Date"]),
                    "ip_hash": row["IP Hash"].strip(),
                    "asn": _normalize_asn(row.get("AS Number", "")),
                    "country": _normalize_country(row.get("Country", "")),
                    "raw": row,
                }
            )
    return rows


def load_raw_rows(csv_path: Path | str) -> List[dict]:
    """Load a raw measurement CSV with timestamp, IP hash, and ASN only."""
    path = Path(csv_path)
    rows: List[dict] = []
    with path.open(newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 2:
                continue
            asn = _normalize_asn(row[2]) if len(row) > 2 else None
            rows.append(
                {
                    "date": _parse_date(row[0]),
                    "ip_hash": row[1].strip(),
                    "asn": asn,
                }
            )
    return rows


def load_dataset(root: Path | str, pool: str, enriched: bool = True) -> List[dict]:
    """Load one of the canonical restricted or unrestricted datasets."""
    root_path = Path(root)
    dataset = DEFAULT_DATASETS[pool]
    path = dataset.enriched if enriched else dataset.raw
    loader = load_enriched_rows if enriched else load_raw_rows
    return loader(root_path / path)


def combine_pools(pool_rows: Mapping[str, Sequence[dict]]) -> List[dict]:
    """Attach a pool label and concatenate rows from multiple pools."""
    combined: List[dict] = []
    for pool, rows in pool_rows.items():
        for row in rows:
            enriched_row = dict(row)
            enriched_row["pool"] = pool
            combined.append(enriched_row)
    return combined


def daily_entity_sets(
    rows: Iterable[Mapping[str, object]],
    field: str,
    ignore_missing: bool = True,
) -> Dict[date, Set[str]]:
    """Map each day to the distinct values of a chosen entity field."""
    daily: MutableMapping[date, Set[str]] = defaultdict(set)
    for row in rows:
        entity = row.get(field)
        day = row["date"]
        if not isinstance(day, date):
            raise TypeError("row['date'] must be a datetime.date")
        if entity is None and ignore_missing:
            continue
        entity_value = str(entity).strip()
        if not entity_value and ignore_missing:
            continue
        daily[day].add(entity_value)
    return {day: daily[day] for day in sorted(daily)}


def compute_daily_churn(daily_sets: Mapping[date, Set[str]]) -> List[dict]:
    """Compute day-over-day churn statistics for an entity set."""
    days = sorted(daily_sets)
    metrics: List[dict] = []
    previous_day: Optional[date] = None
    previous_set: Set[str] = set()

    for current_day in days:
        current_set = set(daily_sets[current_day])
        retained = current_set & previous_set if previous_day is not None else set()
        new_entities = current_set - previous_set if previous_day is not None else set()
        lost_entities = previous_set - current_set if previous_day is not None else set()
        union_size = len(current_set | previous_set) if previous_day is not None else len(current_set)
        metrics.append(
            {
                "date": current_day,
                "current_count": len(current_set),
                "prev_count": len(previous_set) if previous_day is not None else None,
                "retained_count": len(retained) if previous_day is not None else None,
                "new_count": len(new_entities) if previous_day is not None else None,
                "lost_count": len(lost_entities) if previous_day is not None else None,
                "retention_rate": (
                    len(retained) / len(previous_set) if previous_day is not None and previous_set else None
                ),
                "new_rate": (
                    len(new_entities) / len(current_set) if previous_day is not None and current_set else None
                ),
                "loss_rate": (
                    len(lost_entities) / len(previous_set) if previous_day is not None and previous_set else None
                ),
                "jaccard_similarity": (
                    len(retained) / union_size if previous_day is not None and union_size else None
                ),
            }
        )
        previous_day = current_day
        previous_set = current_set
    return metrics


def summarize_churn(metrics: Sequence[Mapping[str, object]]) -> dict:
    """Return concise summary statistics for a churn series."""
    active_counts = [int(entry["current_count"]) for entry in metrics]
    new_rates = [float(entry["new_rate"]) for entry in metrics if entry["new_rate"] is not None]
    retention_rates = [
        float(entry["retention_rate"]) for entry in metrics if entry["retention_rate"] is not None
    ]
    jaccards = [float(entry["jaccard_similarity"]) for entry in metrics if entry["jaccard_similarity"] is not None]
    return {
        "days": len(metrics),
        "avg_daily_count": mean(active_counts) if active_counts else 0.0,
        "median_daily_count": median(active_counts) if active_counts else 0.0,
        "avg_new_rate": mean(new_rates) if new_rates else 0.0,
        "median_new_rate": median(new_rates) if new_rates else 0.0,
        "avg_retention_rate": mean(retention_rates) if retention_rates else 0.0,
        "median_retention_rate": median(retention_rates) if retention_rates else 0.0,
        "median_jaccard_similarity": median(jaccards) if jaccards else 0.0,
    }


def compute_entity_lifetimes(
    daily_sets: Mapping[date, Set[str]],
    min_active_days: int = 1,
) -> List[dict]:
    """Compute first seen, last seen, active days, and span for each entity."""
    first_seen: Dict[str, date] = {}
    last_seen: Dict[str, date] = {}
    active_days: MutableMapping[str, List[date]] = defaultdict(list)

    for day in sorted(daily_sets):
        for entity in daily_sets[day]:
            first_seen.setdefault(entity, day)
            last_seen[entity] = day
            active_days[entity].append(day)

    lifetimes: List[dict] = []
    for entity, days in active_days.items():
        if len(days) < min_active_days:
            continue
        span_days = (last_seen[entity] - first_seen[entity]).days + 1
        lifetimes.append(
            {
                "entity": entity,
                "first_seen": first_seen[entity],
                "last_seen": last_seen[entity],
                "active_days": len(days),
                "span_days": span_days,
                "returning": len(days) > 1,
                "gaps": _count_gaps(days),
            }
        )
    return lifetimes


def _count_gaps(days: Sequence[date]) -> int:
    gaps = 0
    previous = None
    for current in days:
        if previous is not None and (current - previous).days > 1:
            gaps += 1
        previous = current
    return gaps


def load_ipinfo_asn_metadata(csv_path: Path | str) -> Dict[str, dict]:
    """Load ASN-level metadata exported from ipinfo."""
    path = Path(csv_path)
    metadata: Dict[str, dict] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            asn = _normalize_asn(row.get("asn", ""))
            if asn is None or asn in metadata:
                continue
            metadata[asn] = row
    return metadata


def attach_asn_metadata(rows: Iterable[Mapping[str, object]], metadata: Mapping[str, Mapping[str, object]]) -> List[dict]:
    """Join ASN metadata from ipinfo onto measurement rows."""
    enriched_rows: List[dict] = []
    for row in rows:
        merged = dict(row)
        asn = row.get("asn")
        merged["asn_metadata"] = metadata.get(str(asn)) if asn is not None else None
        enriched_rows.append(merged)
    return enriched_rows


def percent(value: Optional[float]) -> str:
    """Format a proportion as a percentage string."""
    if value is None:
        return "NA"
    return f"{value * 100:.2f}%"
