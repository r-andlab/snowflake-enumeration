from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable
import hashlib
import io
import re
import zipfile

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


SPINE_COLOR = "gray"
PROBER_START_HOURS = 24
PAPER_AXIS_LABEL_SIZE = 28
PAPER_TICK_LABEL_SIZE = 28
PAPER_PANEL_TITLE_SIZE = 20
PAPER_TITLE_SIZE = 22
PAPER_LEGEND_SIZE = 25
MODE_LABELS = {
    "enumeration": "Enumeration",
    "blocking": "Blocking",
}
MODE_ALIASES = {
    "enumeration-only": "enumeration",
    "blocking": "blocking",
}
SOURCE_PRIORITIES = {
    "override": 3,
    "filesystem": 2,
    "zip": 1,
}
FACTOR_COLORS = {
    "Churn Rate": "#4e79a7",
    "Attacker Fraction": "#e15759",
    "Connection Duration": "#59a14f",
    "Client Count": "#f28e2b",
    "NAT Distribution": "#76b7b2",
    "Equal Polling Defense": "#9c755f",
    "Baseline": "#222222",
    "Miscellaneous": "#7f7f7f",
}
PROXY_CURVE_META = [
    ("coverage_total_pct", "Total", "#222222", "-"),
    ("coverage_standalone_pct", "Standalone", "#4e79a7", "-"),
    ("coverage_webext_pct", "WebExt", "#f28e2b", "--"),
    ("coverage_iptproxy_pct", "IPT", "#59a14f", ":"),
]
SCENARIO_MARKERS = ["o", "s", "^", "D", "P", "X", "v", "<", ">", "h", "*", "p"]
PROXY_TYPE_MARKERS = {
    "Total": "o",
    "Standalone": "s",
    "WebExt": "^",
    "IPT": "D",
}
CLIENT_REQUEST_OUTCOME_SERIES = [
    ("client_request_success_rate_pct", "Success", "-"),
    ("client_nomatch_blocked_request_rate_pct", "Blocked", "--"),
    ("client_nomatch_no_proxies_request_rate_pct", "No Proxies", "-."),
    ("client_nomatch_timed_out_request_rate_pct", "Timed Out", ":"),
    ("client_nomatch_other_request_rate_pct", "Other", (0, (3, 1, 1, 1))),
]
CHURN_SCENARIO_MULTIPLIERS = {
    "churn_quarter": 0.25,
    "churn_half": 0.50,
    "default_enumeration": 1.00,
    "churn_x2": 2.00,
    "churn_x4": 4.00,
    "churn_x10": 10.00,
}


EXPERIMENT_GROUPS = OrderedDict(
    [
        (
            "Churn Rate",
            [
                ("churn_quarter", "0.25x churn"),
                ("churn_half", "0.5x churn"),
                ("churn_x2", "2x churn"),
                ("churn_x4", "4x churn"),
                ("churn_x10", "10x churn"),
            ],
        ),
        (
            "Attacker Fraction",
            [
                ("attackers_pct_0_001", "0.001% attackers"),
                ("attackers_pct_0_01", "0.01% attackers"),
                ("attackers_pct_0_05", "0.05% attackers"),
                ("attackers_pct_0_1", "0.1% attackers"),
                ("attackers_pct_0_5", "0.5% attackers"),
                ("attackers_pct_1", "1% attackers"),
                ("attackers_pct_5", "5% attackers"),
            ],
        ),
        (
            "Connection Duration",
            [
                ("connection_6h", "6h"),
                ("connection_9h", "9h"),
                ("connection_1_5h_pm15m", "1.5h +/- 15m"),
                ("connection_30m_pm5m", "30m +/- 5m"),
            ],
        ),
        (
            "Client Count",
            [
                ("clients_quarter", "0.25x clients"),
                ("clients_half", "0.5x clients"),
                ("clients_double", "2x clients"),
            ],
        ),
        (
            "NAT Distribution",
            [
                ("nat_dist_0_3", "NAT 0.3 / 0.7"),
                ("nat_dist_0_5", "NAT 0.5 / 0.5"),
            ],
        ),
        (
            "Equal Polling Defense",
            [
                ("equal_defense_10s", "Equal poll 10s"),
                ("equal_defense_120s", "Equal poll 2m"),
                ("equal_defense_240s", "Equal poll 4m"),
            ],
        ),
    ]
)

BASELINE_KEYS = {
    "enumeration": "default_enumeration",
    "blocking": "default_blocking",
}

EXPECTED_BY_MODE = {
    "enumeration": [
        "default_enumeration",
        "churn_quarter",
        "churn_half",
        "churn_x2",
        "churn_x4",
        "churn_x10",
        "connection_6h",
        "connection_9h",
        "connection_1_5h_pm15m",
        "connection_30m_pm5m",
        "clients_quarter",
        "clients_half",
        "clients_double",
        "nat_dist_0_3",
        "nat_dist_0_5",
        "equal_defense_10s",
        "equal_defense_120s",
        "equal_defense_240s",
    ],
    "blocking": [
        "default_blocking",
        "churn_quarter",
        "churn_half",
        "churn_x2",
        "churn_x4",
        "churn_x10",
        "attackers_pct_0_001",
        "attackers_pct_0_01",
        "attackers_pct_0_05",
        "attackers_pct_0_1",
        "attackers_pct_0_5",
        "attackers_pct_1",
        "attackers_pct_5",
        "connection_6h",
        "connection_9h",
        "connection_1_5h_pm15m",
        "connection_30m_pm5m",
        "clients_quarter",
        "clients_half",
        "clients_double",
        "nat_dist_0_3",
        "nat_dist_0_5",
        "equal_defense_10s",
        "equal_defense_120s",
        "equal_defense_240s",
    ],
}


SCENARIO_METADATA: dict[str, dict[str, object]] = {
    "default_enumeration": {
        "factor": "Baseline",
        "label": "Default",
        "factor_order": -1,
        "variant_order": -1,
    },
    "default_blocking": {
        "factor": "Baseline",
        "label": "Default",
        "factor_order": -1,
        "variant_order": -1,
    },
}

for factor_index, (factor, variants) in enumerate(EXPERIMENT_GROUPS.items()):
    for variant_index, (scenario_key, label) in enumerate(variants):
        SCENARIO_METADATA[scenario_key] = {
            "factor": factor,
            "label": label,
            "factor_order": factor_index,
            "variant_order": variant_index,
        }


SCENARIO_ALIASES = {
    "churn_double": "churn_x2",
    "churn_x10": "churn_x10",
    "attacker_0_001": "attackers_pct_0_001",
    "attacker_0_01": "attackers_pct_0_01",
    "attacker_0_05": "attackers_pct_0_05",
    "attacker_0_1": "attackers_pct_0_1",
    "attacker_0_5": "attackers_pct_0_5",
    "attacker_1": "attackers_pct_1",
    "attacker_5": "attackers_pct_5",
    "attackers_pct_0_001": "attackers_pct_0_001",
    "attackers_pct_0_01": "attackers_pct_0_01",
    "attackers_pct_0_05": "attackers_pct_0_05",
    "attackers_pct_0_1": "attackers_pct_0_1",
    "attackers_pct_0_5": "attackers_pct_0_5",
    "attackers_pct_1": "attackers_pct_1",
    "attackers_pct_5": "attackers_pct_5",
    "connection_6h": "connection_6h",
    "connection_9h": "connection_9h",
    "connection_1_5h": "connection_1_5h_pm15m",
    "connection_1_5h_pm15m": "connection_1_5h_pm15m",
    "connection_30m": "connection_30m_pm5m",
    "connection_30m_pm5m": "connection_30m_pm5m",
    "clients_quarter": "clients_quarter",
    "clients_half": "clients_half",
    "clients_double": "clients_double",
    "nat_0_3": "nat_dist_0_3",
    "nat_dist_0_3": "nat_dist_0_3",
    "nat_0_5": "nat_dist_0_5",
    "nat_dist_0_5": "nat_dist_0_5",
    "equal_defense_10s": "equal_defense_10s",
    "equal_defense_120s": "equal_defense_120s",
    "equal_defense_240s": "equal_defense_240s",
    "defense_equal_10s": "equal_defense_10s",
    "defense_equal_120s": "equal_defense_120s",
    "defense_equal_240s": "equal_defense_240s",
    "defense_equal_20s": "equal_defense_20s",
    "defense_equal_60s": "equal_defense_60s",
    "defense_equal_100s": "equal_defense_100s",
    "defense_equal_200s": "equal_defense_200s",
}

SHORT_SCENARIO_LABELS = {
    "default_enumeration": "Default",
    "default_blocking": "Default",
    "churn_quarter": "0.25x",
    "churn_half": "0.5x",
    "churn_x2": "2x",
    "churn_x4": "4x",
    "churn_x10": "10x",
    "attackers_pct_0_001": "0.001%",
    "attackers_pct_0_01": "0.01%",
    "attackers_pct_0_05": "0.05%",
    "attackers_pct_0_1": "0.1%",
    "attackers_pct_0_5": "0.5%",
    "attackers_pct_1": "1%",
    "attackers_pct_5": "5%",
    "connection_6h": "6h",
    "connection_9h": "9h",
    "connection_1_5h_pm15m": "1.5h",
    "connection_30m_pm5m": "30m",
    "clients_quarter": "0.25x",
    "clients_half": "0.5x",
    "clients_double": "2x",
    "nat_dist_0_3": "0.3/0.7",
    "nat_dist_0_5": "0.5/0.5",
    "equal_defense_10s": "10s",
    "equal_defense_120s": "2m",
    "equal_defense_240s": "4m",
    "defense_equal_20s": "20s",
    "defense_equal_60s": "60s",
    "defense_equal_100s": "100s",
    "defense_equal_200s": "200s",
}


CONFIG_RE = re.compile(r"Simulation config: attack_mode=(?P<mode>[^ ]+) attackers=(?P<attackers>\d+)")
STEP_PREFIX_RE = re.compile(r" step-summary t=(?P<t>\S+)")
ACTIVE_COUNTS_RE = re.compile(
    r" clients=(?P<clients>\d+) proxies_total=(?P<active_total>\d+) "
    r"standalone=(?P<active_standalone>\d+) webext=(?P<active_webext>\d+) iptproxy=(?P<active_iptproxy>\d+)"
)
UNIQUE_SEEN_RE = re.compile(
    r" unique_seen clients=(?P<unique_clients>\d+) proxies_total=(?P<unique_total>\d+) "
    r"proxies standalone=(?P<unique_standalone>\d+) webext=(?P<unique_webext>\d+) iptproxy=(?P<unique_iptproxy>\d+)"
)
ATTACKER_UNIQUE_RE = re.compile(
    r" attacker_unique_proxies_total=(?P<attacker_unique_total>\d+) "
    r"attacker_unique_proxies standalone=(?P<attacker_unique_standalone>\d+) "
    r"webext=(?P<attacker_unique_webext>\d+) iptproxy=(?P<attacker_unique_iptproxy>\d+)"
)
RETRY_RE = re.compile(
    r" matches_total=(?P<matches_total>\d+) .*?"
    r"blocked_matches_total=(?P<blocked_matches_total>\d+) .*?"
    r"blocked_retry_events=(?P<blocked_retry_events>\d+) "
    r"blocked_retry_attempts=(?P<blocked_retry_attempts>\d+) "
    r"blocked_retry_avg_per_attempt=(?P<blocked_retry_avg_per_attempt>[0-9.]+) "
    r"blocked_retry_attempt_p25=(?P<blocked_retry_attempt_p25>[0-9.]+) "
    r"blocked_retry_attempt_p50=(?P<blocked_retry_attempt_p50>[0-9.]+) "
    r"blocked_retry_attempt_p75=(?P<blocked_retry_attempt_p75>[0-9.]+) "
    r"blocked_retry_attempt_p99=(?P<blocked_retry_attempt_p99>[0-9.]+) .*?"
    r"total_retry_events=(?P<total_retry_events>\d+) "
    r"total_retry_attempts=(?P<total_retry_attempts>\d+) "
    r"total_retry_avg_per_attempt=(?P<total_retry_avg_per_attempt>[0-9.]+) "
    r"total_retry_attempt_p25=(?P<total_retry_attempt_p25>[0-9.]+) "
    r"total_retry_attempt_p50=(?P<total_retry_attempt_p50>[0-9.]+) "
    r"total_retry_attempt_p75=(?P<total_retry_attempt_p75>[0-9.]+) "
    r"total_retry_attempt_p99=(?P<total_retry_attempt_p99>[0-9.]+) .*?"
    r"client_nomatch_total=(?P<client_nomatch_total>\d+) "
    r"client_nomatch_reasons no_proxies=(?P<client_nomatch_no_proxies>\d+) "
    r"timed_out=(?P<client_nomatch_timed_out>\d+) "
    r"blocked=(?P<client_nomatch_blocked>\d+) "
    r"other=(?P<client_nomatch_other>\d+) .*?"
    r"retry_limit_hits clients=(?P<retry_limit_hits>\d+)"
)
HEAP_RE = re.compile(
    r"step-summary-broker-heaps t=(?P<t>\S+) .*?"
    r"pct_snowflake_heap_never_seen_by_any_attacker=(?P<pct>[0-9.]+)"
)
CLIENT_NAT_RE = re.compile(
    r"step-summary-client-nat t=(?P<t>\S+) "
    r"client_retry_events unrestricted=(?P<retry_u>\d+) restricted=(?P<retry_r>\d+) unknown=(?P<retry_unknown>\d+) "
    r"client_blocked_retries unrestricted=(?P<blocked_u>\d+) restricted=(?P<blocked_r>\d+) unknown=(?P<blocked_unknown>\d+)"
)
MALICIOUS_PROXY_RE = re.compile(
    r"minute-malicious-proxy t=(?P<t>\S+) "
    r"(?P<proxy1>\S+) \((?P<nat1>[^)]+)\) "
    r"pct_match_events_vs_new_connections=(?P<pct1>[0-9.]+) "
    r"match_events=(?P<events1>\d+) "
    r"(?P<proxy2>\S+) \((?P<nat2>[^)]+)\) "
    r"pct_match_events_vs_new_connections=(?P<pct2>[0-9.]+) "
    r"match_events=(?P<events2>\d+) "
    r"total_new_connections_in_minute=(?P<total_new_connections>\d+)"
)


@dataclass(frozen=True)
class SourceRecord:
    locator: str
    source_type: str
    scenario_raw: str
    scenario_key: str
    mode: str
    episode: str
    attackers: int | None
    factor: str
    scenario_label: str
    factor_order: int
    variant_order: int
    display_path: str


def latexify(fig_width: float | None = None, fig_height: float | None = None, columns: int = 1) -> dict[str, object]:
    if columns not in (1, 2):
        raise ValueError("columns must be 1 or 2")
    if fig_width is None:
        fig_width = 3.39 if columns == 1 else 6.9
    if fig_height is None:
        golden_mean = (np.sqrt(5.0) - 1.0) / 2.0
        fig_height = fig_width * golden_mean
    fig_height = min(fig_height, 8.0)
    return {
        "axes.labelsize": PAPER_AXIS_LABEL_SIZE,
        "axes.titlesize": PAPER_PANEL_TITLE_SIZE,
        "font.size": PAPER_AXIS_LABEL_SIZE,
        "legend.fontsize": PAPER_LEGEND_SIZE,
        "xtick.labelsize": PAPER_TICK_LABEL_SIZE,
        "ytick.labelsize": PAPER_TICK_LABEL_SIZE,
        "figure.figsize": [fig_width, fig_height],
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "axes.spines.top": False,
        "axes.spines.right": False,
    }


def format_axes(ax: matplotlib.axes.Axes) -> matplotlib.axes.Axes:
    for spine_name in ("top", "right"):
        ax.spines[spine_name].set_color(SPINE_COLOR)
        ax.spines[spine_name].set_linewidth(0.5)
    for spine_name in ("left", "bottom"):
        ax.spines[spine_name].set_color(SPINE_COLOR)
        ax.spines[spine_name].set_linewidth(0.5)
    ax.xaxis.set_ticks_position("bottom")
    ax.yaxis.set_ticks_position("left")
    ax.tick_params(direction="in", color=SPINE_COLOR)
    return ax


def apply_reference_style() -> None:
    matplotlib.rcParams.update(latexify(columns=2))
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update(
        {
            "grid.linestyle": ":",
            "grid.alpha": 0.25,
            "grid.color": "#444444",
            "axes.edgecolor": SPINE_COLOR,
            "savefig.dpi": 300,
            "axes.titlepad": 10,
            "axes.labelpad": 8,
        }
    )


def style_paper_axes(ax: matplotlib.axes.Axes, *, grid: bool = True) -> matplotlib.axes.Axes:
    if grid:
        ax.grid(True, linestyle=":", linewidth=0.8, color="#444444", alpha=0.35)
    else:
        ax.grid(False)
    ax.tick_params(axis="both", labelsize=PAPER_TICK_LABEL_SIZE, direction="in")
    return format_axes(ax)


def _hours_to_days(x: pd.Series | np.ndarray) -> pd.Series | np.ndarray:
    return x / 24.0


def _day_tick_step(max_days: float) -> float:
    if max_days <= 7:
        return 1.0
    if max_days <= 14:
        return 2.0
    if max_days <= 35:
        return 5.0
    if max_days <= 70:
        return 10.0
    return 20.0


def _set_day_axis(
    ax: matplotlib.axes.Axes,
    hours: pd.Series | np.ndarray,
    *,
    xlabel: str = "Day",
) -> matplotlib.axes.Axes:
    hours_array = np.asarray(hours, dtype=float)
    max_days = max(1.0, float(np.nanmax(hours_array)) / 24.0) if hours_array.size else 1.0
    ax.set_xlim(left=0.0, right=max_days)
    ax.set_xlabel(xlabel, fontsize=PAPER_AXIS_LABEL_SIZE)
    ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(_day_tick_step(max_days)))
    return ax


def _set_day_index_axis(
    ax: matplotlib.axes.Axes,
    day_index: pd.Series | np.ndarray,
    *,
    xlabel: str = "Day",
) -> matplotlib.axes.Axes:
    day_array = np.asarray(day_index, dtype=float)
    max_days = max(1.0, float(np.nanmax(day_array))) if day_array.size else 1.0
    ax.set_xlim(left=1.0, right=max_days)
    ax.set_xlabel(xlabel, fontsize=PAPER_AXIS_LABEL_SIZE)
    ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(_day_tick_step(max_days)))
    return ax


def _plot_hours_series_with_band(
    ax: matplotlib.axes.Axes,
    hours: pd.Series | np.ndarray,
    mean: pd.Series,
    std: pd.Series,
    **kwargs: object,
) -> None:
    _plot_series_with_band(ax, _hours_to_days(hours), mean, std, **kwargs)


def find_repo_root(start: Path | None = None) -> Path:
    candidates = [
        start or Path.cwd(),
        (start or Path.cwd()).parent,
        Path("/Users/ram/repos/r-andlab/snowflake-simulation"),
    ]
    for candidate in candidates:
        candidate = candidate.resolve()
        if (candidate / "broker").exists() and (candidate / "data").exists():
            return candidate
    raise FileNotFoundError("Could not locate the snowflake-simulation repository root")


def default_figure_output_dir(repo_root: Path) -> Path:
    out_dir = repo_root / "notebooks" / "paper_ready_figures" / "simulation_variations"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def save_paper_figure(fig: matplotlib.figure.Figure, out_dir: Path, filename: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / filename
    fig.savefig(target, format="pdf", bbox_inches="tight", pad_inches=0.02)
    return target


def normalize_name(value: str) -> str:
    lowered = value.strip().lower()
    lowered = lowered.replace("%", "pct")
    lowered = lowered.replace(".", "_")
    lowered = lowered.replace("-", "_")
    lowered = lowered.replace(" ", "_")
    lowered = re.sub(r"[^a-z0-9_]+", "_", lowered)
    return re.sub(r"_+", "_", lowered).strip("_")


def humanize_key(key: str) -> str:
    return key.replace("_", " ").strip().title()


def canonicalize_mode(raw_mode: str | None, *, path_hint: str | None = None) -> str | None:
    if raw_mode:
        mode = MODE_ALIASES.get(raw_mode, raw_mode)
        if mode in MODE_LABELS:
            return mode
    if path_hint in MODE_LABELS:
        return path_hint
    return None


def canonicalize_scenario(raw_scenario: str, mode: str | None) -> str:
    normalized = normalize_name(raw_scenario)
    if normalized == "default":
        return BASELINE_KEYS.get(mode or "", "default")
    return str(SCENARIO_ALIASES.get(normalized, normalized))


def metadata_for_scenario(scenario_key: str) -> dict[str, object]:
    meta = SCENARIO_METADATA.get(scenario_key)
    if meta is not None:
        return meta
    return {
        "factor": "Miscellaneous",
        "label": humanize_key(scenario_key),
        "factor_order": len(EXPERIMENT_GROUPS),
        "variant_order": 999,
    }


def _split_locator(locator: str) -> tuple[str, str, str | None]:
    if locator.startswith("file:"):
        return "file", locator.removeprefix("file:"), None
    if locator.startswith("zip:"):
        payload = locator.removeprefix("zip:")
        archive, member = payload.split("::", 1)
        return "zip", archive, member
    raise ValueError(f"Unsupported locator: {locator}")


def _coerce_locator(path_or_locator: str | Path) -> str:
    locator = str(path_or_locator)
    if locator.startswith("file:") or locator.startswith("zip:"):
        return locator
    return f"file:{Path(locator).expanduser().resolve()}"


def _coerce_locators(path_or_locators: str | Path | Iterable[str | Path]) -> list[str]:
    if isinstance(path_or_locators, (str, Path)):
        raw_items: list[str | Path] = [path_or_locators]
    else:
        raw_items = list(path_or_locators)

    locators: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        locator = _coerce_locator(item)
        if locator in seen:
            continue
        seen.add(locator)
        locators.append(locator)
    return locators


def _iter_text_lines(locator: str) -> Iterable[str]:
    kind, path_text, member = _split_locator(locator)
    if kind == "file":
        with Path(path_text).open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line
        return

    archive = zipfile.ZipFile(path_text)
    raw = archive.open(member or "")
    text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
    try:
        for line in text:
            yield line
    finally:
        text.close()
        raw.close()
        archive.close()


def _read_header(locator: str, line_limit: int = 256) -> tuple[str | None, int | None]:
    mode = None
    attackers = None
    for idx, line in enumerate(_iter_text_lines(locator)):
        match = CONFIG_RE.search(line)
        if match:
            mode = canonicalize_mode(match.group("mode"))
            attackers = int(match.group("attackers"))
            break
        if idx + 1 >= line_limit:
            break
    return mode, attackers


def _scenario_from_parts(parts: tuple[str, ...]) -> tuple[str, str]:
    lower_parts = [normalize_name(part) for part in parts]
    if "simulation_results" in lower_parts:
        idx = lower_parts.index("simulation_results")
        scenario = parts[idx + 1] if idx + 1 < len(parts) else "unknown"
    else:
        scenario = parts[-3] if len(parts) >= 3 else "unknown"
    episode = "episode-1"
    for part in parts:
        if re.fullmatch(r"episode-\d+", part.lower()):
            episode = part.lower()
            break
    filename = parts[-1] if parts else ""
    stem = Path(filename).stem.lower()
    sim_match = re.fullmatch(r"sim(?P<index>\d+)", stem)
    if sim_match:
        episode = f"episode-{int(sim_match.group('index'))}"
    return scenario, episode


def _is_simulation_run_log(filename: str) -> bool:
    return re.fullmatch(r"sim(?:\d+)?\.log", filename.lower()) is not None


def _path_mode_hint(parts: tuple[str, ...]) -> str | None:
    lower_parts = {normalize_name(part) for part in parts}
    if "enumeration" in lower_parts:
        return "enumeration"
    if "blocking" in lower_parts:
        return "blocking"
    return None


def _build_record(
    locator: str,
    source_type: str,
    display_path: str,
    scenario_raw: str,
    mode: str | None,
    episode: str,
    attackers: int | None,
) -> SourceRecord | None:
    if mode is None:
        return None
    scenario_key = canonicalize_scenario(scenario_raw, mode)
    meta = metadata_for_scenario(scenario_key)
    return SourceRecord(
        locator=locator,
        source_type=source_type,
        scenario_raw=scenario_raw,
        scenario_key=scenario_key,
        mode=mode,
        episode=episode,
        attackers=attackers,
        factor=str(meta["factor"]),
        scenario_label=str(meta["label"]),
        factor_order=int(meta["factor_order"]),
        variant_order=int(meta["variant_order"]),
        display_path=display_path,
    )


def _candidate_sort_key(record: SourceRecord) -> tuple[int, int]:
    normalized_path = normalize_name(record.display_path)
    mode_specific = int(record.mode in normalized_path)
    path_depth = record.display_path.count("/")
    return (
        SOURCE_PRIORITIES.get(record.source_type, 0),
        mode_specific,
        path_depth,
        len(record.display_path),
    )


def discover_logs(repo_root: Path, baseline_overrides: dict[str, Path | str | None] | None = None) -> pd.DataFrame:
    data_root = repo_root / "data"
    candidates: list[SourceRecord] = []

    for path in sorted((data_root / "Simulation Results").rglob("*.log")):
        if not _is_simulation_run_log(path.name):
            continue
        parts = path.parts
        scenario_raw, episode = _scenario_from_parts(parts)
        mode_hint = _path_mode_hint(parts)
        locator = f"file:{path}"
        mode, attackers = _read_header(locator)
        record = _build_record(
            locator=locator,
            source_type="filesystem",
            display_path=str(path.relative_to(repo_root)),
            scenario_raw=scenario_raw,
            mode=canonicalize_mode(mode, path_hint=mode_hint),
            episode=episode,
            attackers=attackers,
        )
        if record is not None:
            candidates.append(record)

    for archive_path in sorted(data_root.glob("*.zip")):
        with zipfile.ZipFile(archive_path) as archive:
            for member in sorted(archive.namelist()):
                if not member.endswith(".log"):
                    continue
                if not _is_simulation_run_log(Path(member).name):
                    continue
                parts = tuple(part for part in member.split("/") if part)
                scenario_raw, episode = _scenario_from_parts(parts)
                mode_hint = _path_mode_hint(parts)
                locator = f"zip:{archive_path}::{member}"
                mode, attackers = _read_header(locator)
                record = _build_record(
                    locator=locator,
                    source_type="zip",
                    display_path=f"{archive_path.name}:{member}",
                    scenario_raw=scenario_raw,
                    mode=canonicalize_mode(mode, path_hint=mode_hint),
                    episode=episode,
                    attackers=attackers,
                )
                if record is not None:
                    candidates.append(record)

    if baseline_overrides:
        for mode, override_path in baseline_overrides.items():
            if not override_path:
                continue
            path = Path(override_path).expanduser().resolve()
            if not path.exists():
                continue
            locator = f"file:{path}"
            _, attackers = _read_header(locator)
            record = _build_record(
                locator=locator,
                source_type="override",
                display_path=str(path),
                scenario_raw=BASELINE_KEYS[mode],
                mode=mode,
                episode="episode-1",
                attackers=attackers,
            )
            if record is not None:
                candidates.append(record)

    deduped: dict[tuple[str, str, str], SourceRecord] = {}
    for record in candidates:
        key = (record.scenario_key, record.mode, record.episode)
        current = deduped.get(key)
        if current is None or _candidate_sort_key(record) > _candidate_sort_key(current):
            deduped[key] = record

    rows = []
    for record in deduped.values():
        rows.append(
            {
                "locator": record.locator,
                "source_type": record.source_type,
                "display_path": record.display_path,
                "scenario_raw": record.scenario_raw,
                "scenario_key": record.scenario_key,
                "scenario_label": record.scenario_label,
                "mode": record.mode,
                "mode_label": MODE_LABELS[record.mode],
                "episode": record.episode,
                "attackers": record.attackers,
                "factor": record.factor,
                "factor_order": record.factor_order,
                "variant_order": record.variant_order,
            }
        )

    inventory = pd.DataFrame(rows)
    if inventory.empty:
        return inventory
    inventory = inventory.sort_values(
        [
            "mode",
            "factor_order",
            "variant_order",
            "scenario_label",
            "episode",
        ],
        ignore_index=True,
    )
    return inventory


def inventory_display_table(inventory: pd.DataFrame) -> pd.DataFrame:
    if inventory.empty:
        return inventory
    columns = [
        "mode_label",
        "factor",
        "scenario_label",
        "scenario_key",
        "attackers",
        "episode",
        "source_type",
        "display_path",
    ]
    return inventory[columns].rename(
        columns={
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "scenario_key": "Canonical Key",
            "attackers": "Attackers",
            "episode": "Episode",
            "source_type": "Source",
            "display_path": "Path",
        }
    )


def missing_expected_runs(inventory: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for mode, expected_keys in EXPECTED_BY_MODE.items():
        present = set(inventory.loc[inventory["mode"] == mode, "scenario_key"])
        for scenario_key in expected_keys:
            if scenario_key in present:
                continue
            meta = metadata_for_scenario(scenario_key)
            rows.append(
                {
                    "Mode": MODE_LABELS[mode],
                    "Factor": str(meta["factor"]),
                    "Scenario": str(meta["label"]),
                    "Canonical Key": scenario_key,
                }
            )
    return pd.DataFrame(rows)


def _safe_ratio(num: float | int, den: float | int) -> float:
    if float(den) <= 0:
        return float("nan")
    return float(num) / float(den)


def _first_hours_at_or_above(df: pd.DataFrame, column: str, threshold: float) -> float:
    matches = df.loc[df[column] >= threshold, "hours_since_start"]
    if matches.empty:
        return float("nan")
    return float(matches.iloc[0])


def _tail_mean(df: pd.DataFrame, column: str, trailing_hours: float = 24.0) -> float:
    if df.empty:
        return float("nan")
    cutoff = float(df["hours_since_start"].max()) - trailing_hours
    subset = df.loc[df["hours_since_start"] >= cutoff, column]
    if subset.empty:
        subset = df[column]
    return float(subset.mean())


@lru_cache(maxsize=None)
def parse_log_timeseries(locator: str) -> pd.DataFrame:
    rows_by_ts: dict[pd.Timestamp, dict[str, object]] = {}
    heap_pct_by_ts: dict[pd.Timestamp, float] = {}
    client_nat_by_ts: dict[pd.Timestamp, dict[str, int]] = {}

    for line in _iter_text_lines(locator):
        if "step-summary " in line:
            prefix_match = STEP_PREFIX_RE.search(line)
            active_match = ACTIVE_COUNTS_RE.search(line)
            unique_match = UNIQUE_SEEN_RE.search(line)
            attacker_match = ATTACKER_UNIQUE_RE.search(line)
            retry_match = RETRY_RE.search(line)
            if not (prefix_match and active_match and unique_match and attacker_match and retry_match):
                continue
            timestamp = pd.Timestamp(prefix_match.group("t"))
            rows_by_ts[timestamp] = {
                "timestamp": timestamp,
                **{key: int(value) for key, value in active_match.groupdict().items()},
                **{key: int(value) for key, value in unique_match.groupdict().items()},
                **{key: int(value) for key, value in attacker_match.groupdict().items()},
                **{
                    key: (float(value) if ("avg" in key or "_p" in key) else int(value))
                    for key, value in retry_match.groupdict().items()
                },
            }
            continue

        if "step-summary-broker-heaps " in line:
            match = HEAP_RE.search(line)
            if match:
                heap_pct_by_ts[pd.Timestamp(match.group("t"))] = float(match.group("pct"))
            continue

        if "step-summary-client-nat " in line:
            match = CLIENT_NAT_RE.search(line)
            if match:
                timestamp = pd.Timestamp(match.group("t"))
                client_nat_by_ts[timestamp] = {
                    key: int(value)
                    for key, value in match.groupdict().items()
                    if key != "t"
                }

    if not rows_by_ts:
        return pd.DataFrame()

    df = pd.DataFrame(rows_by_ts.values()).sort_values("timestamp").reset_index(drop=True)
    df["heap_never_seen_pct"] = df["timestamp"].map(heap_pct_by_ts)

    client_nat_df = pd.DataFrame(
        [{"timestamp": ts, **values} for ts, values in client_nat_by_ts.items()]
    )
    if not client_nat_df.empty:
        df = df.merge(client_nat_df, on="timestamp", how="left")

    df["hours_since_start"] = (
        (df["timestamp"] - df["timestamp"].iloc[0]).dt.total_seconds() / 3600.0
    )

    coverage_pairs = [
        ("total", "unique_total", "attacker_unique_total"),
        ("standalone", "unique_standalone", "attacker_unique_standalone"),
        ("webext", "unique_webext", "attacker_unique_webext"),
        ("iptproxy", "unique_iptproxy", "attacker_unique_iptproxy"),
    ]
    for suffix, den_col, num_col in coverage_pairs:
        df[f"coverage_{suffix}"] = np.where(
            df[den_col] > 0,
            df[num_col] / df[den_col],
            np.nan,
        )
        df[f"coverage_{suffix}_pct"] = df[f"coverage_{suffix}"] * 100.0

    df["client_request_events_total"] = df["matches_total"] + df["total_retry_events"]
    df["client_request_success_rate"] = np.where(
        df["client_request_events_total"] > 0,
        df["matches_total"] / df["client_request_events_total"],
        np.nan,
    )
    df["client_request_success_rate_pct"] = df["client_request_success_rate"] * 100.0
    df["client_request_unsuccessful_rate"] = np.where(
        df["client_request_events_total"] > 0,
        df["total_retry_events"] / df["client_request_events_total"],
        np.nan,
    )
    df["client_request_unsuccessful_rate_pct"] = df["client_request_unsuccessful_rate"] * 100.0
    df["client_nomatch_reason_total"] = (
        df["client_nomatch_blocked"]
        + df["client_nomatch_no_proxies"]
        + df["client_nomatch_timed_out"]
        + df["client_nomatch_other"]
    )
    for suffix in ("blocked", "no_proxies", "timed_out", "other"):
        count_col = f"client_nomatch_{suffix}"
        share_col = f"{count_col}_share"
        request_rate_col = f"{count_col}_request_rate"
        if count_col not in df.columns:
            continue
        df[share_col] = np.where(
            df["client_nomatch_reason_total"] > 0,
            df[count_col] / df["client_nomatch_reason_total"],
            np.nan,
        )
        df[f"{share_col}_pct"] = df[share_col] * 100.0
        df[request_rate_col] = np.where(
            df["client_request_events_total"] > 0,
            df[count_col] / df["client_request_events_total"],
            np.nan,
        )
        df[f"{request_rate_col}_pct"] = df[request_rate_col] * 100.0
    df["completed_attempts_total"] = df["matches_total"] + df["retry_limit_hits"]
    df["blocked_retry_attempt_rate"] = np.where(
        df["completed_attempts_total"] > 0,
        df["blocked_retry_attempts"] / df["completed_attempts_total"],
        np.nan,
    )
    df["blocked_retry_attempt_rate_pct"] = df["blocked_retry_attempt_rate"] * 100.0
    df["any_retry_attempt_rate"] = np.where(
        df["completed_attempts_total"] > 0,
        df["total_retry_attempts"] / df["completed_attempts_total"],
        np.nan,
    )
    df["any_retry_attempt_rate_pct"] = df["any_retry_attempt_rate"] * 100.0
    df["first_try_success_rate"] = np.where(
        df["completed_attempts_total"] > 0,
        (df["completed_attempts_total"] - df["total_retry_attempts"]) / df["completed_attempts_total"],
        np.nan,
    )
    df["first_try_success_pct"] = df["first_try_success_rate"] * 100.0
    df["heap_seen_pct"] = 100.0 - df["heap_never_seen_pct"]

    for nat in ("u", "r", "unknown"):
        retry_col = f"retry_{nat}"
        blocked_col = f"blocked_{nat}"
        if retry_col in df.columns and blocked_col in df.columns:
            df[f"blocked_retry_share_{nat}"] = np.where(
                df[retry_col] > 0,
                df[blocked_col] / df[retry_col],
                np.nan,
            )
            df[f"blocked_retry_share_{nat}_pct"] = df[f"blocked_retry_share_{nat}"] * 100.0

    return df


@lru_cache(maxsize=None)
def parse_malicious_proxy_timeseries(path_or_locator: str | Path) -> pd.DataFrame:
    rows: list[dict[str, object]] = []

    for line in _iter_text_lines(_coerce_locator(path_or_locator)):
        match = MALICIOUS_PROXY_RE.search(line)
        if not match:
            continue

        timestamp = pd.Timestamp(match.group("t"))
        total_new_connections = int(match.group("total_new_connections"))
        row: dict[str, object] = {
            "timestamp": timestamp,
            "total_new_connections_in_minute": total_new_connections,
        }
        combined_match_events = 0
        for index in (1, 2):
            nat = normalize_name(match.group(f"nat{index}"))
            match_events = int(match.group(f"events{index}"))
            offer_fraction = float(match.group(f"pct{index}"))
            row[f"{nat}_proxy_key"] = str(match.group(f"proxy{index}"))
            row[f"{nat}_match_events"] = match_events
            row[f"{nat}_offer_fraction"] = offer_fraction
            row[f"{nat}_offer_rate_pct"] = offer_fraction * 100.0
            combined_match_events += match_events

        row["combined_match_events"] = combined_match_events
        row["combined_offer_fraction"] = _safe_ratio(combined_match_events, total_new_connections)
        row["combined_offer_rate_pct"] = float(row["combined_offer_fraction"]) * 100.0
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    for nat in ("unrestricted", "restricted"):
        for suffix, default in (
            ("proxy_key", pd.NA),
            ("match_events", 0),
            ("offer_fraction", 0.0),
            ("offer_rate_pct", 0.0),
        ):
            column = f"{nat}_{suffix}"
            if column not in df.columns:
                df[column] = default

    df["hours_since_start"] = (
        (df["timestamp"] - df["timestamp"].iloc[0]).dt.total_seconds() / 3600.0
    )
    return df


def aggregate_malicious_proxy_timeseries(
    timeseries: pd.DataFrame,
    *,
    hours_per_bucket: float = 1.0,
) -> pd.DataFrame:
    if timeseries.empty:
        return timeseries

    bucket_seconds = max(60, int(round(hours_per_bucket * 3600.0)))
    working = timeseries.copy()
    working["bucket_timestamp"] = working["timestamp"].dt.floor(f"{bucket_seconds}s")
    aggregated = (
        working.groupby("bucket_timestamp", as_index=False)
        .agg(
            total_new_connections_in_bucket=("total_new_connections_in_minute", "sum"),
            combined_match_events=("combined_match_events", "sum"),
            unrestricted_match_events=("unrestricted_match_events", "sum"),
            restricted_match_events=("restricted_match_events", "sum"),
        )
        .sort_values("bucket_timestamp")
        .reset_index(drop=True)
    )

    for prefix in ("combined", "unrestricted", "restricted"):
        aggregated[f"{prefix}_offer_fraction"] = np.where(
            aggregated["total_new_connections_in_bucket"] > 0,
            aggregated[f"{prefix}_match_events"] / aggregated["total_new_connections_in_bucket"],
            np.nan,
        )
        aggregated[f"{prefix}_offer_rate_pct"] = aggregated[f"{prefix}_offer_fraction"] * 100.0

    aggregated["hours_since_start"] = (
        (aggregated["bucket_timestamp"] - aggregated["bucket_timestamp"].iloc[0]).dt.total_seconds()
        / 3600.0
    )
    return aggregated


def aggregate_malicious_proxy_offer_rate_runs(
    path_or_locators: str | Path | Iterable[str | Path],
    *,
    hours_per_bucket: float = 1.0,
) -> pd.DataFrame:
    aggregated_runs: list[pd.DataFrame] = []
    for episode_index, locator in enumerate(_coerce_locators(path_or_locators), start=1):
        timeseries = parse_malicious_proxy_timeseries(locator)
        if timeseries.empty:
            continue
        aggregated = aggregate_malicious_proxy_timeseries(
            timeseries,
            hours_per_bucket=hours_per_bucket,
        )
        if aggregated.empty:
            continue
        working = aggregated.copy()
        working["bucket_index"] = np.arange(len(working))
        working["episode"] = episode_index
        aggregated_runs.append(working)

    if not aggregated_runs:
        return pd.DataFrame()

    combined = pd.concat(aggregated_runs, ignore_index=True)
    numeric_cols = [
        "hours_since_start",
        "total_new_connections_in_bucket",
        "combined_match_events",
        "unrestricted_match_events",
        "restricted_match_events",
        "combined_offer_fraction",
        "unrestricted_offer_fraction",
        "restricted_offer_fraction",
        "combined_offer_rate_pct",
        "unrestricted_offer_rate_pct",
        "restricted_offer_rate_pct",
    ]
    agg = (
        combined.groupby("bucket_index", dropna=False)[numeric_cols]
        .agg(["mean", "std"])
        .reset_index()
    )
    agg.columns = [
        "bucket_index"
        if column == ("bucket_index", "")
        else f"{column[0]}_{column[1]}"
        for column in agg.columns.to_flat_index()
    ]
    std_cols = [column for column in agg.columns if column.endswith("_std")]
    agg[std_cols] = agg[std_cols].fillna(0.0)
    agg["episodes"] = len(aggregated_runs)
    return agg.sort_values("bucket_index", ignore_index=True)


def summarize_malicious_proxy_offer_rate(
    path_or_locators: str | Path | Iterable[str | Path],
) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for locator in _coerce_locators(path_or_locators):
        timeseries = parse_malicious_proxy_timeseries(locator)
        if timeseries.empty:
            continue

        total_new_connections = int(timeseries["total_new_connections_in_minute"].sum())
        rows.append(
            {
                "locator": locator,
                "duration_days": float(timeseries["hours_since_start"].max() / 24.0),
                "total_new_connections": total_new_connections,
                "mean_combined_offer_rate_pct": float(
                    100.0 * timeseries["combined_match_events"].sum() / total_new_connections
                )
                if total_new_connections > 0
                else float("nan"),
                "peak_combined_offer_rate_pct": float(timeseries["combined_offer_rate_pct"].max()),
                "mean_unrestricted_offer_rate_pct": float(
                    100.0 * timeseries["unrestricted_match_events"].sum() / total_new_connections
                )
                if total_new_connections > 0
                else float("nan"),
                "peak_unrestricted_offer_rate_pct": float(timeseries["unrestricted_offer_rate_pct"].max()),
                "mean_restricted_offer_rate_pct": float(
                    100.0 * timeseries["restricted_match_events"].sum() / total_new_connections
                )
                if total_new_connections > 0
                else float("nan"),
                "peak_restricted_offer_rate_pct": float(timeseries["restricted_offer_rate_pct"].max()),
                "total_combined_match_events": int(timeseries["combined_match_events"].sum()),
                "total_unrestricted_match_events": int(timeseries["unrestricted_match_events"].sum()),
                "total_restricted_match_events": int(timeseries["restricted_match_events"].sum()),
            }
        )

    if not rows:
        return pd.DataFrame()

    if len(rows) == 1:
        return pd.DataFrame(rows)

    per_run = pd.DataFrame(rows)
    summary = {
        "episodes": len(per_run),
        "duration_days_mean": float(per_run["duration_days"].mean()),
        "duration_days_std": float(per_run["duration_days"].std(ddof=0)),
        "total_new_connections_mean": float(per_run["total_new_connections"].mean()),
        "total_new_connections_std": float(per_run["total_new_connections"].std(ddof=0)),
        "mean_combined_offer_rate_pct_mean": float(per_run["mean_combined_offer_rate_pct"].mean()),
        "mean_combined_offer_rate_pct_std": float(per_run["mean_combined_offer_rate_pct"].std(ddof=0)),
        "peak_combined_offer_rate_pct_mean": float(per_run["peak_combined_offer_rate_pct"].mean()),
        "peak_combined_offer_rate_pct_std": float(per_run["peak_combined_offer_rate_pct"].std(ddof=0)),
        "mean_unrestricted_offer_rate_pct_mean": float(per_run["mean_unrestricted_offer_rate_pct"].mean()),
        "mean_unrestricted_offer_rate_pct_std": float(per_run["mean_unrestricted_offer_rate_pct"].std(ddof=0)),
        "peak_unrestricted_offer_rate_pct_mean": float(per_run["peak_unrestricted_offer_rate_pct"].mean()),
        "peak_unrestricted_offer_rate_pct_std": float(per_run["peak_unrestricted_offer_rate_pct"].std(ddof=0)),
        "mean_restricted_offer_rate_pct_mean": float(per_run["mean_restricted_offer_rate_pct"].mean()),
        "mean_restricted_offer_rate_pct_std": float(per_run["mean_restricted_offer_rate_pct"].std(ddof=0)),
        "peak_restricted_offer_rate_pct_mean": float(per_run["peak_restricted_offer_rate_pct"].mean()),
        "peak_restricted_offer_rate_pct_std": float(per_run["peak_restricted_offer_rate_pct"].std(ddof=0)),
        "total_combined_match_events_mean": float(per_run["total_combined_match_events"].mean()),
        "total_combined_match_events_std": float(per_run["total_combined_match_events"].std(ddof=0)),
        "total_unrestricted_match_events_mean": float(per_run["total_unrestricted_match_events"].mean()),
        "total_unrestricted_match_events_std": float(per_run["total_unrestricted_match_events"].std(ddof=0)),
        "total_restricted_match_events_mean": float(per_run["total_restricted_match_events"].mean()),
        "total_restricted_match_events_std": float(per_run["total_restricted_match_events"].std(ddof=0)),
    }
    return pd.DataFrame([summary])


def summarize_malicious_proxy_offer_rate_single(path_or_locator: str | Path) -> pd.DataFrame:
    timeseries = parse_malicious_proxy_timeseries(path_or_locator)
    if timeseries.empty:
        return pd.DataFrame()

    total_new_connections = int(timeseries["total_new_connections_in_minute"].sum())
    summary = {
        "duration_days": float(timeseries["hours_since_start"].max() / 24.0),
        "total_new_connections": total_new_connections,
        "mean_combined_offer_rate_pct": float(
            100.0 * timeseries["combined_match_events"].sum() / total_new_connections
        )
        if total_new_connections > 0
        else float("nan"),
        "peak_combined_offer_rate_pct": float(timeseries["combined_offer_rate_pct"].max()),
        "mean_unrestricted_offer_rate_pct": float(
            100.0 * timeseries["unrestricted_match_events"].sum() / total_new_connections
        )
        if total_new_connections > 0
        else float("nan"),
        "peak_unrestricted_offer_rate_pct": float(timeseries["unrestricted_offer_rate_pct"].max()),
        "mean_restricted_offer_rate_pct": float(
            100.0 * timeseries["restricted_match_events"].sum() / total_new_connections
        )
        if total_new_connections > 0
        else float("nan"),
        "peak_restricted_offer_rate_pct": float(timeseries["restricted_offer_rate_pct"].max()),
        "total_combined_match_events": int(timeseries["combined_match_events"].sum()),
        "total_unrestricted_match_events": int(timeseries["unrestricted_match_events"].sum()),
        "total_restricted_match_events": int(timeseries["restricted_match_events"].sum()),
    }
    return pd.DataFrame([summary])


def summarize_runs(inventory: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for record in inventory.to_dict("records"):
        timeseries = parse_log_timeseries(record["locator"])
        if timeseries.empty:
            continue
        final = timeseries.iloc[-1]
        duration_hours = float(final["hours_since_start"])
        if duration_hours > 0:
            mean_coverage_total = float(
                np.trapz(timeseries["coverage_total"], timeseries["hours_since_start"]) / duration_hours
            )
        else:
            mean_coverage_total = float(final["coverage_total"])
        rows.append(
            {
                **record,
                "duration_hours": duration_hours,
                "final_coverage_total_pct": float(final["coverage_total_pct"]),
                "final_coverage_standalone_pct": float(final["coverage_standalone_pct"]),
                "final_coverage_webext_pct": float(final["coverage_webext_pct"]),
                "final_coverage_iptproxy_pct": float(final["coverage_iptproxy_pct"]),
                "mean_coverage_total_pct": mean_coverage_total * 100.0,
                "hours_to_50pct_total": _first_hours_at_or_above(timeseries, "coverage_total_pct", 50.0),
                "hours_to_90pct_total": _first_hours_at_or_above(timeseries, "coverage_total_pct", 90.0),
                "final_heap_never_seen_pct": float(final["heap_never_seen_pct"]),
                "final_heap_seen_pct": float(final["heap_seen_pct"]),
                "final_blocked_retry_attempt_rate_pct": float(final["blocked_retry_attempt_rate_pct"]),
                "final_any_retry_attempt_rate_pct": float(final["any_retry_attempt_rate_pct"]),
                "final_first_try_success_pct": float(final["first_try_success_pct"]),
                "final_blocked_retry_avg": float(final["blocked_retry_avg_per_attempt"]),
                "last_day_blocked_retry_avg": _tail_mean(timeseries, "blocked_retry_avg_per_attempt"),
                "last_day_blocked_retry_attempt_rate_pct": _tail_mean(
                    timeseries, "blocked_retry_attempt_rate_pct"
                ),
                "final_total_retry_avg": float(final["total_retry_avg_per_attempt"]),
                "final_blocked_nomatch_share_pct": float(final["client_nomatch_blocked_share_pct"]),
                "last_day_blocked_nomatch_share_pct": _tail_mean(
                    timeseries, "client_nomatch_blocked_share_pct"
                ),
            }
        )

    summary = pd.DataFrame(rows)
    if summary.empty:
        return summary
    summary = summary.sort_values(
        ["mode", "factor_order", "variant_order", "scenario_label"],
        ignore_index=True,
    )
    return attach_baseline_deltas(summary)


def attach_baseline_deltas(summary: pd.DataFrame) -> pd.DataFrame:
    if summary.empty:
        return summary
    out = summary.copy()
    delta_metrics = [
        "final_coverage_total_pct",
        "mean_coverage_total_pct",
        "final_blocked_retry_attempt_rate_pct",
        "final_blocked_retry_avg",
        "last_day_blocked_retry_avg",
        "final_blocked_nomatch_share_pct",
        "final_heap_never_seen_pct",
    ]
    for metric in delta_metrics:
        out[f"{metric}_delta_vs_baseline"] = np.nan
        out[f"{metric}_ratio_vs_baseline"] = np.nan

    for mode, baseline_key in BASELINE_KEYS.items():
        baseline_rows = out[(out["mode"] == mode) & (out["scenario_key"] == baseline_key)]
        if baseline_rows.empty:
            continue
        baseline_row = baseline_rows.iloc[0]
        mask = out["mode"] == mode
        for metric in delta_metrics:
            out.loc[mask, f"{metric}_delta_vs_baseline"] = out.loc[mask, metric] - float(
                baseline_row[metric]
            )
            baseline_value = float(baseline_row[metric])
            if baseline_value != 0:
                out.loc[mask, f"{metric}_ratio_vs_baseline"] = out.loc[mask, metric] / baseline_value
    return out


def summary_display_table(summary: pd.DataFrame) -> pd.DataFrame:
    if summary.empty:
        return summary
    columns = [
        "mode_label",
        "factor",
        "scenario_label",
        "attackers",
        "final_coverage_total_pct",
        "mean_coverage_total_pct",
        "final_blocked_retry_attempt_rate_pct",
        "final_blocked_retry_avg",
        "last_day_blocked_retry_avg",
        "final_blocked_nomatch_share_pct",
        "final_heap_never_seen_pct",
    ]
    renamed = summary[columns].rename(
        columns={
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "attackers": "Attackers",
            "final_coverage_total_pct": "Final Coverage (%)",
            "mean_coverage_total_pct": "Mean Coverage (%)",
            "final_blocked_retry_attempt_rate_pct": "Attempts w/ >=1 Blocked Retry (%)",
            "final_blocked_retry_avg": "Final Blocked Retries",
            "last_day_blocked_retry_avg": "Last-Day Blocked Retries",
            "final_blocked_nomatch_share_pct": "Blocked No-Match Share (%)",
            "final_heap_never_seen_pct": "Heap Never Seen (%)",
        }
    )
    return renamed


def summarize_scenarios(summary: pd.DataFrame) -> pd.DataFrame:
    if summary.empty:
        return summary

    numeric_metrics = [
        "duration_hours",
        "final_coverage_total_pct",
        "final_coverage_standalone_pct",
        "final_coverage_webext_pct",
        "final_coverage_iptproxy_pct",
        "mean_coverage_total_pct",
        "hours_to_50pct_total",
        "hours_to_90pct_total",
        "final_heap_never_seen_pct",
        "final_heap_seen_pct",
        "final_blocked_retry_attempt_rate_pct",
        "last_day_blocked_retry_attempt_rate_pct",
        "final_any_retry_attempt_rate_pct",
        "final_first_try_success_pct",
        "final_blocked_retry_avg",
        "last_day_blocked_retry_avg",
        "final_total_retry_avg",
        "final_blocked_nomatch_share_pct",
        "last_day_blocked_nomatch_share_pct",
    ]
    group_cols = [
        "mode",
        "mode_label",
        "factor",
        "factor_order",
        "variant_order",
        "scenario_key",
        "scenario_label",
    ]

    grouped = summary.groupby(group_cols, dropna=False)
    rows = []
    for keys, group in grouped:
        row = {col: value for col, value in zip(group_cols, keys)}
        row["episodes"] = len(group)
        row["episodes_label"] = f"{len(group)} episode" if len(group) == 1 else f"{len(group)} episodes"
        row["attackers_mean"] = float(group["attackers"].mean()) if "attackers" in group else np.nan
        row["attackers_min"] = float(group["attackers"].min()) if "attackers" in group else np.nan
        row["attackers_max"] = float(group["attackers"].max()) if "attackers" in group else np.nan
        for metric in numeric_metrics:
            row[f"{metric}_mean"] = float(group[metric].mean())
            row[f"{metric}_std"] = float(group[metric].std(ddof=0)) if len(group) > 1 else 0.0
        rows.append(row)

    scenario_summary = pd.DataFrame(rows).sort_values(
        ["mode", "factor_order", "variant_order", "scenario_label"],
        ignore_index=True,
    )
    return attach_baseline_deltas_to_scenarios(scenario_summary)


def attach_baseline_deltas_to_scenarios(scenario_summary: pd.DataFrame) -> pd.DataFrame:
    if scenario_summary.empty:
        return scenario_summary
    out = scenario_summary.copy()
    delta_metrics = [
        "final_coverage_total_pct_mean",
        "mean_coverage_total_pct_mean",
        "final_blocked_retry_attempt_rate_pct_mean",
        "final_blocked_retry_avg_mean",
        "last_day_blocked_retry_avg_mean",
        "final_blocked_nomatch_share_pct_mean",
        "final_heap_never_seen_pct_mean",
    ]
    for metric in delta_metrics:
        out[f"{metric}_delta_vs_baseline"] = np.nan
        out[f"{metric}_ratio_vs_baseline"] = np.nan

    for mode, baseline_key in BASELINE_KEYS.items():
        baseline_rows = out[(out["mode"] == mode) & (out["scenario_key"] == baseline_key)]
        if baseline_rows.empty:
            continue
        baseline_row = baseline_rows.iloc[0]
        mask = out["mode"] == mode
        for metric in delta_metrics:
            out.loc[mask, f"{metric}_delta_vs_baseline"] = out.loc[mask, metric] - float(
                baseline_row[metric]
            )
            baseline_value = float(baseline_row[metric])
            if baseline_value != 0:
                out.loc[mask, f"{metric}_ratio_vs_baseline"] = out.loc[mask, metric] / baseline_value
    return out


def scenario_summary_display_table(scenario_summary: pd.DataFrame) -> pd.DataFrame:
    if scenario_summary.empty:
        return scenario_summary
    columns = [
        "mode_label",
        "factor",
        "scenario_label",
        "episodes",
        "attackers_mean",
        "final_coverage_total_pct_mean",
        "final_coverage_total_pct_std",
        "final_blocked_retry_attempt_rate_pct_mean",
        "final_blocked_retry_attempt_rate_pct_std",
        "final_blocked_retry_avg_mean",
        "final_blocked_retry_avg_std",
        "final_heap_never_seen_pct_mean",
    ]
    renamed = scenario_summary[columns].rename(
        columns={
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "episodes": "Episodes",
            "attackers_mean": "Attackers (mean)",
            "final_coverage_total_pct_mean": "Final Coverage Mean (%)",
            "final_coverage_total_pct_std": "Final Coverage Std (%)",
            "final_blocked_retry_attempt_rate_pct_mean": "Blocked Attempt Mean (%)",
            "final_blocked_retry_attempt_rate_pct_std": "Blocked Attempt Std",
            "final_blocked_retry_avg_mean": "Blocked Retries Mean",
            "final_blocked_retry_avg_std": "Blocked Retries Std",
            "final_heap_never_seen_pct_mean": "Heap Never Seen Mean (%)",
        }
    )
    return renamed


def _is_metric_outlier(
    value: float | int | None,
    reference: float | int | None,
    *,
    abs_threshold: float,
    low_ratio: float,
    high_ratio: float,
) -> bool:
    if value is None or reference is None:
        return False
    if pd.isna(value) or pd.isna(reference):
        return False
    value_f = float(value)
    reference_f = float(reference)
    if abs(value_f - reference_f) <= abs_threshold:
        return False
    if reference_f == 0.0:
        return abs(value_f) > abs_threshold
    ratio = value_f / reference_f
    return ratio < low_ratio or ratio > high_ratio


def detect_anomalous_runs(
    summary: pd.DataFrame,
    *,
    min_repeat_runs: int = 2,
    short_run_threshold_hours: float = 700.0,
    enum_coverage_abs_threshold: float = 5.0,
    enum_coverage_low_ratio: float = 0.90,
    enum_coverage_high_ratio: float = 1.10,
    enum_heap_abs_threshold: float = 5.0,
    enum_heap_low_ratio: float = 0.90,
    enum_heap_high_ratio: float = 1.10,
    enum_blocked_retry_threshold: float = 0.10,
    enum_blocked_attempt_threshold: float = 0.10,
    block_retry_abs_threshold: float = 5.0,
    block_retry_low_ratio: float = 0.70,
    block_retry_high_ratio: float = 1.30,
    block_attempt_abs_threshold: float = 10.0,
    block_attempt_low_ratio: float = 0.80,
    block_attempt_high_ratio: float = 1.20,
    block_coverage_abs_threshold: float = 5.0,
    block_coverage_low_ratio: float = 0.90,
    block_coverage_high_ratio: float = 1.10,
) -> pd.DataFrame:
    if summary.empty:
        return pd.DataFrame()

    repeated = (
        summary.groupby(["mode", "scenario_key"])
        .size()
        .reset_index(name="episodes_here")
    )
    repeated = repeated[repeated["episodes_here"] >= min_repeat_runs]
    if repeated.empty:
        return pd.DataFrame()

    repeated_keys = {
        (row["mode"], row["scenario_key"])
        for row in repeated.to_dict("records")
    }

    findings: list[dict[str, object]] = []
    for (mode, scenario_key), records in summary.groupby(["mode", "scenario_key"], sort=False):
        has_repeats = (mode, scenario_key) in repeated_keys

        records = records.sort_values("episode", ignore_index=True)
        attackers_present = sorted(
            {int(value) for value in records["attackers"].dropna().tolist()}
        )
        config_mismatch = len(attackers_present) > 1

        coverage_median = float(records["final_coverage_total_pct"].median())
        heap_seen_median = float(records["final_heap_seen_pct"].median())
        blocked_retry_median = float(records["final_blocked_retry_avg"].median())
        blocked_attempt_median = float(records["final_blocked_retry_attempt_rate_pct"].median())

        for row in records.to_dict("records"):
            reasons: list[str] = []

            if config_mismatch and has_repeats:
                attacker_text = ", ".join(str(value) for value in attackers_present)
                reasons.append(f"attacker-count mismatch within scenario ({attacker_text})")

            if (
                row["factor"] != "Miscellaneous"
                and pd.notna(row["duration_hours"])
                and float(row["duration_hours"]) < short_run_threshold_hours
            ):
                reasons.append(
                    f"run ended early at {float(row['duration_hours']):.1f}h"
                )

            if mode == "enumeration":
                if has_repeats:
                    if _is_metric_outlier(
                        row["final_coverage_total_pct"],
                        coverage_median,
                        abs_threshold=enum_coverage_abs_threshold,
                        low_ratio=enum_coverage_low_ratio,
                        high_ratio=enum_coverage_high_ratio,
                    ):
                        reasons.append(
                            f"final coverage {row['final_coverage_total_pct']:.2f}% vs sibling median {coverage_median:.2f}%"
                        )
                    if _is_metric_outlier(
                        row["final_heap_seen_pct"],
                        heap_seen_median,
                        abs_threshold=enum_heap_abs_threshold,
                        low_ratio=enum_heap_low_ratio,
                        high_ratio=enum_heap_high_ratio,
                    ):
                        reasons.append(
                            f"active-heap visibility {row['final_heap_seen_pct']:.2f}% vs sibling median {heap_seen_median:.2f}%"
                        )
                if (
                    float(row["final_blocked_retry_avg"]) > enum_blocked_retry_threshold
                    or float(row["final_blocked_retry_attempt_rate_pct"]) > enum_blocked_attempt_threshold
                ):
                    reasons.append(
                        "enumeration run has nonzero blocking metrics"
                    )
            else:
                if has_repeats:
                    if _is_metric_outlier(
                        row["final_blocked_retry_avg"],
                        blocked_retry_median,
                        abs_threshold=block_retry_abs_threshold,
                        low_ratio=block_retry_low_ratio,
                        high_ratio=block_retry_high_ratio,
                    ):
                        reasons.append(
                            f"blocked retries {row['final_blocked_retry_avg']:.2f} vs sibling median {blocked_retry_median:.2f}"
                        )
                    if _is_metric_outlier(
                        row["final_blocked_retry_attempt_rate_pct"],
                        blocked_attempt_median,
                        abs_threshold=block_attempt_abs_threshold,
                        low_ratio=block_attempt_low_ratio,
                        high_ratio=block_attempt_high_ratio,
                    ):
                        reasons.append(
                            f"blocked-attempt rate {row['final_blocked_retry_attempt_rate_pct']:.2f}% vs sibling median {blocked_attempt_median:.2f}%"
                        )
                    if _is_metric_outlier(
                        row["final_coverage_total_pct"],
                        coverage_median,
                        abs_threshold=block_coverage_abs_threshold,
                        low_ratio=block_coverage_low_ratio,
                        high_ratio=block_coverage_high_ratio,
                    ):
                        reasons.append(
                            f"final coverage {row['final_coverage_total_pct']:.2f}% vs sibling median {coverage_median:.2f}%"
                        )

            if reasons:
                findings.append(
                    {
                        "mode_label": row["mode_label"],
                        "factor": row["factor"],
                        "scenario_label": row["scenario_label"],
                        "scenario_key": row["scenario_key"],
                        "episode": row["episode"],
                        "attackers": row["attackers"],
                        "final_coverage_total_pct": row["final_coverage_total_pct"],
                        "final_heap_seen_pct": row["final_heap_seen_pct"],
                        "final_blocked_retry_attempt_rate_pct": row["final_blocked_retry_attempt_rate_pct"],
                        "final_blocked_retry_avg": row["final_blocked_retry_avg"],
                        "display_path": row["display_path"],
                        "reason": "; ".join(reasons),
                    }
                )

    if not findings:
        return pd.DataFrame()

    out = pd.DataFrame(findings).sort_values(
        ["mode_label", "factor", "scenario_label", "episode"],
        ignore_index=True,
    )
    return out


def anomaly_display_table(anomalies: pd.DataFrame) -> pd.DataFrame:
    if anomalies.empty:
        return anomalies
    return anomalies[
        [
            "mode_label",
            "factor",
            "scenario_label",
            "episode",
            "attackers",
            "final_coverage_total_pct",
            "final_heap_seen_pct",
            "final_blocked_retry_attempt_rate_pct",
            "final_blocked_retry_avg",
            "reason",
            "display_path",
        ]
    ].rename(
        columns={
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "episode": "Episode",
            "attackers": "Attackers",
            "final_coverage_total_pct": "Final Coverage (%)",
            "final_heap_seen_pct": "Visible Active Heap (%)",
            "final_blocked_retry_attempt_rate_pct": "Blocked Attempt Rate (%)",
            "final_blocked_retry_avg": "Blocked Retries Avg",
            "reason": "Why Flagged",
            "display_path": "Path",
        }
    )


@lru_cache(maxsize=None)
def _log_content_fingerprint(locator: str) -> tuple[str, int, str]:
    hasher = hashlib.sha256()
    line_count = 0
    last_step_summary = ""
    for line in _iter_text_lines(locator):
        line_count += 1
        hasher.update(line.encode("utf-8", errors="replace"))
        if "step-summary " in line:
            last_step_summary = line.strip()
    return hasher.hexdigest(), line_count, last_step_summary


def detect_duplicate_log_contents(inventory: pd.DataFrame) -> pd.DataFrame:
    if inventory.empty:
        return pd.DataFrame()

    rows = []
    for record in inventory.to_dict("records"):
        sha256, line_count, last_step_summary = _log_content_fingerprint(record["locator"])
        rows.append(
            {
                **record,
                "sha256": sha256,
                "sha256_prefix": sha256[:12],
                "line_count": line_count,
                "last_step_summary": last_step_summary,
            }
        )

    fingerprints = pd.DataFrame(rows)
    duplicate_groups = fingerprints.groupby("sha256").size().reset_index(name="duplicate_group_size")
    duplicate_groups = duplicate_groups[duplicate_groups["duplicate_group_size"] > 1]
    if duplicate_groups.empty:
        return pd.DataFrame()

    out = fingerprints.merge(duplicate_groups, on="sha256", how="inner")
    return out.sort_values(
        ["duplicate_group_size", "sha256", "mode", "factor_order", "variant_order", "episode"],
        ascending=[False, True, True, True, True, True],
        ignore_index=True,
    )


def duplicate_log_display_table(duplicates: pd.DataFrame) -> pd.DataFrame:
    if duplicates.empty:
        return duplicates
    return duplicates[
        [
            "duplicate_group_size",
            "sha256_prefix",
            "mode_label",
            "factor",
            "scenario_label",
            "episode",
            "attackers",
            "line_count",
            "display_path",
        ]
    ].rename(
        columns={
            "duplicate_group_size": "Duplicate Group Size",
            "sha256_prefix": "SHA256 Prefix",
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "episode": "Episode",
            "attackers": "Attackers",
            "line_count": "Lines",
            "display_path": "Path",
        }
    )


def active_heap_enumeration_table(
    scenario_summary: pd.DataFrame,
    *,
    mode: str = "enumeration",
) -> pd.DataFrame:
    if scenario_summary.empty:
        return scenario_summary

    subset = scenario_summary[scenario_summary["mode"] == mode].copy()
    if subset.empty:
        return subset

    columns = [
        "mode_label",
        "factor",
        "scenario_label",
        "episodes",
        "final_coverage_total_pct_mean",
        "final_heap_seen_pct_mean",
        "final_heap_seen_pct_std",
        "final_heap_never_seen_pct_mean",
        "final_heap_never_seen_pct_std",
    ]
    renamed = subset[columns].rename(
        columns={
            "mode_label": "Mode",
            "factor": "Factor",
            "scenario_label": "Scenario",
            "episodes": "Episodes",
            "final_coverage_total_pct_mean": "Final Coverage (%)",
            "final_heap_seen_pct_mean": "Visible Active Heap Mean (%)",
            "final_heap_seen_pct_std": "Visible Active Heap Std (%)",
            "final_heap_never_seen_pct_mean": "Unseen Active Heap Mean (%)",
            "final_heap_never_seen_pct_std": "Unseen Active Heap Std (%)",
        }
    )
    return renamed.sort_values(["Factor", "Scenario"], ignore_index=True)


def aggregate_scenario_timeseries(records: pd.DataFrame) -> pd.DataFrame:
    if records.empty:
        return pd.DataFrame()

    timeseries_rows = []
    for _, row in records.iterrows():
        df = parse_log_timeseries(row["locator"])
        if df.empty:
            continue
        enriched = df.copy()
        enriched["episode"] = row["episode"]
        timeseries_rows.append(enriched)

    if not timeseries_rows:
        return pd.DataFrame()

    combined = pd.concat(timeseries_rows, ignore_index=True)
    numeric_cols = [
        column
        for column in combined.select_dtypes(include=[np.number]).columns.tolist()
        if column != "hours_since_start"
    ]

    agg = (
        combined.groupby("hours_since_start", dropna=False)[numeric_cols]
        .agg(["mean", "std"])
        .reset_index()
    )
    agg.columns = [
        "hours_since_start"
        if column == ("hours_since_start", "")
        else f"{column[0]}_{column[1]}"
        for column in agg.columns.to_flat_index()
    ]
    std_cols = [col for col in agg.columns if col.endswith("_std")]
    agg[std_cols] = agg[std_cols].fillna(0.0)
    agg = agg.assign(episodes=len(timeseries_rows))
    return agg.sort_values("hours_since_start", ignore_index=True)


def _subset_for_factor(inventory: pd.DataFrame, factor: str, mode: str) -> pd.DataFrame:
    subset = inventory[(inventory["factor"] == factor) & (inventory["mode"] == mode)].copy()
    baseline_key = BASELINE_KEYS[mode]
    baseline_rows = inventory[
        (inventory["scenario_key"] == baseline_key) & (inventory["mode"] == mode)
    ]
    if not baseline_rows.empty:
        subset = pd.concat([baseline_rows, subset], ignore_index=True)
    if subset.empty:
        return subset
    subset = subset.drop_duplicates(subset=["scenario_key", "mode", "episode"]).copy()
    subset["baseline_order"] = (subset["scenario_key"] != baseline_key).astype(int)
    subset = subset.sort_values(
        ["baseline_order", "variant_order", "scenario_label", "episode"],
        ignore_index=True,
    )
    return subset


def _scenario_color_map(subset: pd.DataFrame) -> dict[str, str]:
    ordered_keys = list(OrderedDict.fromkeys(subset["scenario_key"]))
    color_cycle = plt.get_cmap("tab10").colors
    mapping: dict[str, str] = {}
    color_index = 0
    for key in ordered_keys:
        if key in BASELINE_KEYS.values():
            mapping[key] = "#222222"
            continue
        mapping[key] = color_cycle[color_index % len(color_cycle)]
        color_index += 1
    return mapping


def short_label_for_scenario(scenario_key: str) -> str:
    return SHORT_SCENARIO_LABELS.get(
        scenario_key,
        str(metadata_for_scenario(scenario_key).get("label", scenario_key)),
    )


def _scenario_plot_label(
    scenario_row: pd.Series,
    episodes: int,
    *,
    short: bool = False,
    include_episodes: bool = True,
) -> str:
    label = (
        short_label_for_scenario(str(scenario_row["scenario_key"]))
        if short
        else str(scenario_row["scenario_label"])
    )
    if include_episodes and episodes > 1:
        label = f"{label} (n={episodes})"
    return label


def _marker_for_scenario(scenario_key: str) -> str:
    if scenario_key in BASELINE_KEYS.values():
        return "o"
    ordered_keys = [
        key
        for key, metadata in sorted(
            SCENARIO_METADATA.items(),
            key=lambda item: (
                int(item[1].get("factor_order", 999)),
                int(item[1].get("variant_order", 999)),
                str(item[0]),
            ),
        )
        if key not in BASELINE_KEYS.values()
    ]
    try:
        index = ordered_keys.index(scenario_key)
    except ValueError:
        index = sum(ord(char) for char in scenario_key)
    return SCENARIO_MARKERS[index % len(SCENARIO_MARKERS)]


def _markevery_for_series(x: pd.Series | np.ndarray, *, target_markers: int = 14) -> int:
    count = max(1, len(x))
    return max(1, count // target_markers)


def _compact_single_axis_width(line_count: int, *, base: float = 6.9, per_extra: float = 0.5) -> float:
    return base + max(0, line_count - 4) * per_extra


def _display_factor_name(factor: str) -> str:
    return "Default" if factor == "Baseline" else factor


def _scenario_records_for_plot(subset: pd.DataFrame) -> list[tuple[pd.Series, pd.DataFrame]]:
    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(
        ["baseline_order", "variant_order", "scenario_label"],
        ignore_index=True,
    )
    scenario_records: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_timeseries(records)
        if aggregated.empty:
            continue
        scenario_records.append((scenario_row, aggregated))
    return scenario_records


def _cumulative_trapezoid(x: pd.Series | np.ndarray, y: pd.Series | np.ndarray) -> np.ndarray:
    x_arr = np.asarray(x, dtype=float)
    y_arr = np.asarray(y, dtype=float)
    if x_arr.size == 0:
        return np.array([], dtype=float)
    out = np.zeros_like(x_arr, dtype=float)
    if x_arr.size == 1:
        return out
    out[1:] = np.cumsum(np.diff(x_arr) * (y_arr[:-1] + y_arr[1:]) / 2.0)
    return out


def _cumulative_series_from_band(
    x: pd.Series,
    mean: pd.Series,
    std: pd.Series,
) -> tuple[pd.Series, pd.Series]:
    index = mean.index
    mean_arr = np.asarray(mean, dtype=float)
    std_arr = np.asarray(std.fillna(0.0), dtype=float)
    lower_arr = mean_arr - std_arr
    upper_arr = mean_arr + std_arr

    cumulative_mean = _cumulative_trapezoid(x, mean_arr)
    cumulative_lower = _cumulative_trapezoid(x, lower_arr)
    cumulative_upper = _cumulative_trapezoid(x, upper_arr)
    cumulative_std = (cumulative_upper - cumulative_lower) / 2.0
    return pd.Series(cumulative_mean, index=index), pd.Series(cumulative_std, index=index)


def _grid_shape(panel_count: int) -> tuple[int, int]:
    if panel_count <= 1:
        return 1, 1
    if panel_count == 2:
        return 1, 2
    if panel_count == 3:
        return 1, 3
    if panel_count == 4:
        return 2, 2
    if panel_count <= 6:
        return 2, 3
    return 2, 4


def _baseline_timeseries(inventory: pd.DataFrame, mode: str) -> pd.DataFrame:
    baseline_rows = inventory[
        (inventory["scenario_key"] == BASELINE_KEYS[mode]) & (inventory["mode"] == mode)
    ].copy()
    if baseline_rows.empty:
        return pd.DataFrame()
    return aggregate_scenario_timeseries(baseline_rows)


def _scenario_subset_without_baseline(inventory: pd.DataFrame, factor: str, mode: str) -> pd.DataFrame:
    subset = inventory[(inventory["factor"] == factor) & (inventory["mode"] == mode)].copy()
    if subset.empty:
        return subset
    subset = subset[subset["scenario_key"] != BASELINE_KEYS[mode]].copy()
    subset = subset.sort_values(["variant_order", "scenario_label", "episode"], ignore_index=True)
    return subset


def _delta_vs_baseline(
    scenario_timeseries: pd.DataFrame,
    baseline_timeseries: pd.DataFrame,
    columns: list[str],
) -> pd.DataFrame:
    if scenario_timeseries.empty or baseline_timeseries.empty:
        return pd.DataFrame()

    scenario_cols = ["hours_since_start", "episodes"] + [
        item for column in columns for item in (f"{column}_mean", f"{column}_std")
    ]
    baseline_cols = ["hours_since_start", "episodes"] + [
        item for column in columns for item in (f"{column}_mean", f"{column}_std")
    ]

    merged = scenario_timeseries[scenario_cols].merge(
        baseline_timeseries[baseline_cols],
        on="hours_since_start",
        how="inner",
        suffixes=("_scenario", "_baseline"),
    )
    if merged.empty:
        return merged

    for column in columns:
        merged[f"{column}_delta_mean"] = (
            merged[f"{column}_mean_scenario"] - merged[f"{column}_mean_baseline"]
        )
        merged[f"{column}_delta_std"] = np.sqrt(
            np.square(merged[f"{column}_std_scenario"]) + np.square(merged[f"{column}_std_baseline"])
        )
    merged["episodes_scenario"] = merged["episodes_scenario"].astype(int)
    merged["episodes_baseline"] = merged["episodes_baseline"].astype(int)
    return merged


def plot_factor_enumeration(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "enumeration")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    appendix_axis_label_size = PAPER_AXIS_LABEL_SIZE + 6
    appendix_tick_label_size = PAPER_TICK_LABEL_SIZE + 4
    appendix_panel_title_size = PAPER_PANEL_TITLE_SIZE + 2
    appendix_legend_size = PAPER_LEGEND_SIZE + 2
    metrics = [
        ("coverage_total_pct", "Total"),
        ("coverage_standalone_pct", "Standalone"),
        ("coverage_webext_pct", "WebExt"),
        ("coverage_iptproxy_pct", "IPT"),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(23.4, 4.5), sharex=True, sharey=True)
    for ax, (column, panel_title) in zip(np.atleast_1d(axes).flatten(), metrics):
        for row, aggregated in scenario_records:
            scenario_key = row["scenario_key"]
            is_baseline = scenario_key == BASELINE_KEYS["enumeration"]
            label = _scenario_plot_label(
                row,
                int(aggregated["episodes"].iloc[0]),
                short=True,
                include_episodes=False,
            )
            _plot_hours_series_with_band(
                ax,
                aggregated["hours_since_start"],
                aggregated[f"{column}_mean"],
                aggregated[f"{column}_std"],
                color=color_map[scenario_key],
                label=label,
                linewidth=2.8 if is_baseline else 2.1,
                alpha=0.95 if is_baseline else 0.9,
                marker=_marker_for_scenario(str(scenario_key)),
                markersize=8.0,
                markevery=_markevery_for_series(aggregated["hours_since_start"]),
                lower_clip=0.0,
                upper_clip=100.0,
            )
        ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
        ax.set_title(panel_title, fontsize=appendix_panel_title_size)
        ax.set_ylim(0, 100)
        _set_day_axis(ax, aggregated["hours_since_start"])
        style_paper_axes(ax)
        ax.set_xlabel("Day", fontsize=appendix_axis_label_size)
        ax.tick_params(axis="both", labelsize=appendix_tick_label_size, direction="in")
    axes[0].set_ylabel("Coverage (%)", fontsize=appendix_axis_label_size)

    handles, labels = np.atleast_1d(axes).flatten()[0].get_legend_handles_labels()
    dedup_handles = []
    dedup_labels = []
    for handle, label in zip(handles, labels):
        if label in dedup_labels:
            continue
        dedup_handles.append(handle)
        dedup_labels.append(label)
    np.atleast_1d(axes).flatten()[-1].legend(
        dedup_handles,
        dedup_labels,
        loc="lower right",
        ncol=1,
        frameon=True,
        fontsize=appendix_legend_size,
        borderpad=0.25,
        labelspacing=0.18,
        handlelength=1.2,
        handletextpad=0.45,
    )
    fig.subplots_adjust(left=0.07, right=0.995, bottom=0.24, top=0.86, wspace=0.12)
    return fig


def plot_enumeration_baseline_proxy_overlay(
    inventory: pd.DataFrame,
    *,
    title_suffix: str = "",
    standalone_label: str = "Standalone",
    standalone_comparison_inventory: pd.DataFrame | None = None,
    standalone_comparison_label: str = "Standalone comparison",
    standalone_default_inventory: pd.DataFrame | None = None,
    standalone_default_label: str = "Standalone (default)",
) -> matplotlib.figure.Figure | None:
    baseline_rows = inventory[
        (inventory["scenario_key"] == BASELINE_KEYS["enumeration"])
        & (inventory["mode"] == "enumeration")
    ].copy()
    if baseline_rows.empty:
        return None

    aggregated = aggregate_scenario_timeseries(baseline_rows)
    if aggregated.empty:
        return None

    comparison = pd.DataFrame()
    if (
        standalone_comparison_inventory is not None
        and not standalone_comparison_inventory.empty
    ):
        comparison_rows = standalone_comparison_inventory[
            (
                standalone_comparison_inventory["scenario_key"]
                == BASELINE_KEYS["enumeration"]
            )
            & (standalone_comparison_inventory["mode"] == "enumeration")
        ].copy()
        comparison = aggregate_scenario_timeseries(comparison_rows)

    standalone_default = pd.DataFrame()
    if (
        standalone_default_inventory is not None
        and not standalone_default_inventory.empty
    ):
        standalone_default_rows = standalone_default_inventory[
            (
                standalone_default_inventory["scenario_key"]
                == BASELINE_KEYS["enumeration"]
            )
            & (standalone_default_inventory["mode"] == "enumeration")
        ].copy()
        standalone_default = aggregate_scenario_timeseries(standalone_default_rows)

    metric_specs = [
        ("coverage_total_pct", "Total", "#222222", 3.0),
        ("coverage_standalone_pct", standalone_label, "#1f77b4", 2.3),
        ("coverage_webext_pct", "WebExt", "#ff7f0e", 2.3),
        ("coverage_iptproxy_pct", "IPT", "#2ca02c", 2.3),
    ]
    appendix_axis_label_size = PAPER_AXIS_LABEL_SIZE + 6
    appendix_tick_label_size = PAPER_TICK_LABEL_SIZE + 4
    has_standalone_comparison = not comparison.empty or not standalone_default.empty
    appendix_legend_size = (
        PAPER_LEGEND_SIZE - 4
        if has_standalone_comparison
        else PAPER_LEGEND_SIZE + 2
    )

    fig, ax = plt.subplots(
        figsize=(10.8, 4.8) if has_standalone_comparison else (8.2, 4.5)
    )
    for column, label, color, linewidth in metric_specs:
        mean = aggregated[f"{column}_mean"]
        std = aggregated[f"{column}_std"].fillna(0.0)
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            mean,
            std,
            color=color,
            linewidth=linewidth,
            alpha=0.96,
            label=label,
            linestyle=next(
                linestyle
                for proxy_column, proxy_label, _, linestyle in PROXY_CURVE_META
                if proxy_column == column
            ),
            marker=next(
                PROXY_TYPE_MARKERS[proxy_label]
                for proxy_column, proxy_label, _, _ in PROXY_CURVE_META
                if proxy_column == column
            ),
            markersize=8.0,
            markevery=_markevery_for_series(aggregated["hours_since_start"], target_markers=12),
        )

    if has_standalone_comparison:
        if not comparison.empty:
            _plot_hours_series_with_band(
                ax,
                comparison["hours_since_start"],
                comparison["coverage_standalone_pct_mean"],
                comparison["coverage_standalone_pct_std"].fillna(0.0),
                color="#9467bd",
                linewidth=2.3,
                alpha=0.96,
                label=standalone_comparison_label,
                linestyle="-.",
                marker="P",
                markersize=8.0,
                markevery=_markevery_for_series(
                    comparison["hours_since_start"],
                    target_markers=12,
                ),
            )

        if not standalone_default.empty:
            _plot_hours_series_with_band(
                ax,
                standalone_default["hours_since_start"],
                standalone_default["coverage_standalone_pct_mean"],
                standalone_default["coverage_standalone_pct_std"].fillna(0.0),
                color="#d62728",
                linewidth=2.3,
                alpha=0.96,
                label=standalone_default_label,
                linestyle="--",
                marker="X",
                markersize=8.0,
                markevery=_markevery_for_series(
                    standalone_default["hours_since_start"],
                    target_markers=12,
                ),
            )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_xlabel("Day", fontsize=appendix_axis_label_size)
    ax.set_ylabel("Coverage (%)", fontsize=appendix_axis_label_size)
    style_paper_axes(ax)
    ax.tick_params(axis="both", labelsize=appendix_tick_label_size, direction="in")
    ax.legend(
        loc="lower right",
        ncol=1,
        frameon=True,
        fontsize=appendix_legend_size,
        borderpad=0.25,
        labelspacing=0.18,
        handlelength=1.2,
        handletextpad=0.45,
    )
    fig.subplots_adjust(left=0.16, right=0.995, bottom=0.28, top=0.96)
    return fig


def plot_factor_blocking(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    fig, axes = plt.subplots(1, 2, figsize=(14.2, 4.3), sharex=True)

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = row["scenario_label"]
        if int(aggregated["episodes"].iloc[0]) > 1:
            label = f"{label} (n={int(aggregated['episodes'].iloc[0])})"
        marker = _marker_for_scenario(str(scenario_key))
        markevery = _markevery_for_series(aggregated["hours_since_start"])
        _plot_hours_series_with_band(
            axes[0],
            aggregated["hours_since_start"],
            aggregated["coverage_total_pct_mean"],
            aggregated["coverage_total_pct_std"],
            color=color_map[scenario_key],
            label=label,
            linewidth=2.8 if is_baseline else 2.1,
            alpha=0.95 if is_baseline else 0.9,
            marker=marker,
            markevery=markevery,
            lower_clip=0.0,
            upper_clip=100.0,
            
        )

        retry_mean = aggregated["blocked_retry_avg_per_attempt_mean"].replace(0, np.nan)
        _plot_hours_series_with_band(
            axes[1],
            aggregated["hours_since_start"],
            retry_mean,
            aggregated["blocked_retry_avg_per_attempt_std"].fillna(0.0),
            color=color_map[scenario_key],
            label=label,
            linewidth=2.8 if is_baseline else 2.1,
            alpha=0.95 if is_baseline else 0.9,
            marker=marker,
            markevery=markevery,
            lower_clip=0.5,
        )

    axes[0].axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
    axes[0].set_title("Coverage", fontsize=PAPER_PANEL_TITLE_SIZE)
    axes[0].set_ylabel("Unique proxies found (%)", fontsize=PAPER_AXIS_LABEL_SIZE)
    axes[0].set_ylim(0, 100)
    _set_day_axis(axes[0], scenario_records[0][1]["hours_since_start"])
    style_paper_axes(axes[0])

    axes[1].axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
    axes[1].set_title("Client Retry Burden", fontsize=PAPER_PANEL_TITLE_SIZE)
    axes[1].set_ylabel("Client Retries (log)", fontsize=PAPER_AXIS_LABEL_SIZE)
    _set_day_axis(axes[1], scenario_records[0][1]["hours_since_start"])
    axes[1].set_yscale("log")
    axes[1].set_ylim(bottom=0.5)
    style_paper_axes(axes[1])

    handles, labels = axes[0].get_legend_handles_labels()
    dedup_handles = []
    dedup_labels = []
    for handle, label in zip(handles, labels):
        if label in dedup_labels:
            continue
        dedup_handles.append(handle)
        dedup_labels.append(label)
    fig.legend(
        dedup_handles,
        dedup_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.02),
        ncol=max(1, len(dedup_labels)),
        frameon=True,
        fontsize=max(PAPER_LEGEND_SIZE - 2, 10),
        borderpad=0.25,
        labelspacing=0.20,
        handlelength=1.3,
        handletextpad=0.40,
        columnspacing=0.90,
    )
    fig.subplots_adjust(left=0.08, right=0.995, bottom=0.22, top=0.80, wspace=0.18)
    return fig


def plot_factor_enumeration_coverage_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    proxy_type: str = "total",
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    if proxy_type not in {"total", "standalone", "webext", "iptproxy"}:
        raise ValueError(f"Unknown proxy type: {proxy_type}")
    coverage_column = f"coverage_{proxy_type}_pct"
    subset = _subset_for_factor(inventory, factor, "enumeration")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    compact_axis_label_size = PAPER_AXIS_LABEL_SIZE + 6
    compact_tick_label_size = PAPER_TICK_LABEL_SIZE + 4
    compact_legend_size = PAPER_LEGEND_SIZE + 2
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=7.2, per_extra=0.50), 4.2)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["enumeration"]
        label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            aggregated[f"{coverage_column}_mean"],
            aggregated[f"{coverage_column}_std"],
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markersize=8.2,
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_xlabel("Day", fontsize=compact_axis_label_size)
    ax.set_ylabel("Coverage (%)", fontsize=compact_axis_label_size)
    style_paper_axes(ax)
    ax.tick_params(axis="both", labelsize=compact_tick_label_size, direction="in")

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=compact_legend_size,
        borderpad=0.25,
        labelspacing=0.18,
        handlelength=1.2,
        handletextpad=0.45,
        ncol=1,
    )
    fig.subplots_adjust(left=0.15, right=0.995, bottom=0.28, top=0.96)
    return fig


def plot_factor_enumeration_total_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    return plot_factor_enumeration_coverage_only(
        inventory, factor, title_suffix=title_suffix
    )


def plot_factor_active_heap_seen_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "enumeration")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["enumeration"]
        label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            aggregated["heap_seen_pct_mean"],
            aggregated["heap_seen_pct_std"],
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("Visible Active Heap (%)", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
        ncol=6,
    )
    fig.subplots_adjust(left=0.15, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_retry_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        retry_mean = aggregated["blocked_retry_avg_per_attempt_mean"].replace(0, np.nan)
        retry_std = aggregated["blocked_retry_avg_per_attempt_std"].fillna(0.0)
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            retry_mean,
            retry_std,
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.5,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_yscale("log")
    ax.set_ylim(bottom=0.5)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("Client Retries (log)", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
        ncol=6,
    )
    fig.subplots_adjust(left=0.13, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_blocked_attempt_rate_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        attempt_rate_mean = aggregated["blocked_retry_attempt_rate_pct_mean"]
        attempt_rate_std = aggregated["blocked_retry_attempt_rate_pct_std"].fillna(0.0)
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            attempt_rate_mean,
            attempt_rate_std,
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("% Attempts w/ >=1 Retry", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.15, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_unsuccessful_request_rate_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        unsuccessful_mean = aggregated["client_request_unsuccessful_rate_pct_mean"]
        unsuccessful_std = aggregated["client_request_unsuccessful_rate_pct_std"].fillna(0.0)
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            unsuccessful_mean,
            unsuccessful_std,
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("% Unsuccessful", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.15, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_daily_unsuccessful_request_rate_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    hours_per_bucket: float = 24.0,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_daily_request_harm_records(
        subset,
        hours_per_bucket=hours_per_bucket,
    )
    if not scenario_records:
        return None

    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, daily in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = _scenario_plot_label(
            row,
            int(daily["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        unsuccessful_mean = daily["delta_unsuccessful_request_rate_pct_mean"]
        unsuccessful_std = daily["delta_unsuccessful_request_rate_pct_std"].fillna(0.0)
        _plot_series_with_band(
            ax,
            daily["day_index"],
            unsuccessful_mean,
            unsuccessful_std,
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(daily["day_index"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.set_ylim(0, 100)
    _set_day_index_axis(ax, scenario_records[0][1]["day_index"])
    ax.set_ylabel("% Requests Unsuccess.", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.15, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_daily_retry_cost_only(
    inventory: pd.DataFrame,
    factor: str,
    *,
    hours_per_bucket: float = 24.0,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_daily_request_harm_records(
        subset,
        hours_per_bucket=hours_per_bucket,
    )
    if not scenario_records:
        return None

    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=6.8, per_extra=0.45), 4.0)
    )

    for row, daily in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        label = _scenario_plot_label(
            row,
            int(daily["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        retry_mean = daily["delta_retry_events_per_completed_attempt_mean"].replace(0, np.nan)
        retry_std = daily["delta_retry_events_per_completed_attempt_std"].fillna(0.0)
        _plot_series_with_band(
            ax,
            daily["day_index"],
            retry_mean,
            retry_std,
            color=color_map[scenario_key],
            label=label,
            linewidth=2.9 if is_baseline else 2.2,
            alpha=0.96 if is_baseline else 0.92,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(daily["day_index"]),
            lower_clip=0.5,
        )

    ax.set_yscale("log")
    ax.set_ylim(bottom=0.5)
    _set_day_index_axis(ax, scenario_records[0][1]["day_index"])
    ax.set_ylabel("Retry Events / Completed Attempt (log)", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        labels,
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.3,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.17, right=0.995, bottom=0.23, top=0.94)
    return fig


def plot_factor_blocking_nomatch_reason_panels(
    inventory: pd.DataFrame,
    factor: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    color_map = _scenario_color_map(subset)
    scenario_records = _scenario_records_for_plot(subset)
    if not scenario_records:
        return None

    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=9.2, per_extra=0.8), 4.6)
    )

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS["blocking"]
        scenario_label = _scenario_plot_label(
            row,
            int(aggregated["episodes"].iloc[0]),
            short=True,
            include_episodes=False,
        )
        scenario_color = color_map[scenario_key]
        scenario_marker = _marker_for_scenario(str(scenario_key))
        marker_step = _markevery_for_series(aggregated["hours_since_start"], target_markers=10)

        for metric_col, _, linestyle in CLIENT_REQUEST_OUTCOME_SERIES:
            mean_col = f"{metric_col}_mean"
            std_col = f"{metric_col}_std"
            if mean_col not in aggregated.columns:
                continue
            _plot_hours_series_with_band(
                ax,
                aggregated["hours_since_start"],
                aggregated[mean_col],
                aggregated[std_col].fillna(0.0),
                color=scenario_color,
                label=scenario_label,
                linewidth=2.9 if is_baseline else 2.2,
                alpha=0.95 if is_baseline else 0.88,
                linestyle=linestyle,
                marker=scenario_marker,
                markevery=marker_step,
                lower_clip=0.0,
                upper_clip=100.0,
            )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.1, alpha=0.8)
    ax.set_ylim(0, 100)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("% Client Requests", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    scenario_handles = []
    scenario_labels = []
    for row, aggregated in scenario_records:
        scenario_key = str(row["scenario_key"])
        scenario_handles.append(
            matplotlib.lines.Line2D(
                [],
                [],
                color=color_map[scenario_key],
                linestyle="-",
                linewidth=2.4 if scenario_key == BASELINE_KEYS["blocking"] else 2.0,
                marker=_marker_for_scenario(scenario_key),
                markersize=7.6,
                markerfacecolor="white",
                markeredgewidth=1.1,
            )
        )
        scenario_labels.append(
            _scenario_plot_label(
                row,
                int(aggregated["episodes"].iloc[0]),
                short=True,
                include_episodes=False,
            )
        )

    scenario_legend = ax.legend(
        scenario_handles,
        scenario_labels,
        loc="upper left",
        bbox_to_anchor=(1.01, 1.00),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE - 2,
        borderpad=0.30,
        labelspacing=0.22,
        handlelength=1.4,
        handletextpad=0.45,
        borderaxespad=0.0,
    )
    ax.add_artist(scenario_legend)

    reason_handles = [
        matplotlib.lines.Line2D([], [], color="#333333", linestyle=linestyle, linewidth=2.3)
        for _, _, linestyle in CLIENT_REQUEST_OUTCOME_SERIES
    ]
    reason_labels = [label for _, label, _ in CLIENT_REQUEST_OUTCOME_SERIES]
    ax.legend(
        reason_handles,
        reason_labels,
        loc="lower left",
        bbox_to_anchor=(1.01, 0.00),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE - 2,
        borderpad=0.30,
        labelspacing=0.22,
        handlelength=1.8,
        handletextpad=0.55,
        borderaxespad=0.0,
    )
    fig.subplots_adjust(left=0.11, right=0.77, bottom=0.23, top=0.94)
    return fig


def plot_blocking_retry_daily_boxes(
    inventory: pd.DataFrame,
    factor: str,
    *,
    retry_prefix: str = "blocked_retry_attempt",
    hours_per_bucket: float = 24.0,
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    scenario_records = _scenario_daily_retry_records(
        subset,
        retry_prefix=retry_prefix,
        hours_per_bucket=hours_per_bucket,
    )
    if not scenario_records:
        return None

    rows, cols = _grid_shape(len(scenario_records))
    fig_width = 6.6 * cols
    fig_height = 4.2 * rows
    fig, axes = plt.subplots(rows, cols, figsize=(fig_width, fig_height), squeeze=False, sharey=True)
    axes_flat = axes.flatten()
    color_map = _scenario_color_map(subset)
    log_floor = 0.05
    ymax = log_floor

    for ax, (scenario_row, daily) in zip(axes_flat, scenario_records):
        color = color_map[scenario_row["scenario_key"]]
        for _, day_row in daily.iterrows():
            day = float(day_row["day_index"])
            q25 = max(log_floor, float(day_row["retry_p25_mean"]))
            q50 = max(log_floor, float(day_row["retry_p50_mean"]))
            q75 = max(log_floor, float(day_row["retry_p75_mean"]))
            q99 = max(log_floor, float(day_row["retry_p99_mean"]))
            ymax = max(ymax, q99)

            ax.vlines(day, q25, q99, color=color, linewidth=1.5, alpha=0.95)
            rect_height = max(q75 - q25, 0.03)
            rect = matplotlib.patches.Rectangle(
                (day - 0.34, q25),
                0.68,
                rect_height,
                facecolor=color,
                edgecolor=color,
                alpha=0.22,
                linewidth=1.3,
            )
            ax.add_patch(rect)
            ax.hlines(q50, day - 0.34, day + 0.34, color=color, linewidth=2.0)

        ax.plot(
            daily["day_index"],
            daily["retry_p50_mean"],
            color=color,
            linewidth=1.5,
            marker=_marker_for_scenario(str(scenario_row["scenario_key"])),
            markersize=7.0,
            markerfacecolor="white",
            markeredgewidth=1.1,
        )
        ax.set_title(
            _scenario_plot_label(scenario_row, int(daily["episodes"].iloc[0]), short=True, include_episodes=False),
            fontsize=PAPER_PANEL_TITLE_SIZE,
        )
        ax.set_xlabel("Day", fontsize=PAPER_AXIS_LABEL_SIZE)
        ax.set_xlim(0.5, max(1.5, float(daily["day_index"].max()) + 0.5))
        style_paper_axes(ax)

    for ax in axes_flat[len(scenario_records):]:
        ax.set_visible(False)

    axes_flat[0].set_ylabel("Client Retries (log)", fontsize=PAPER_AXIS_LABEL_SIZE)
    upper = max(1.0, ymax * 1.08)
    for ax in axes_flat[: len(scenario_records)]:
        ax.set_yscale("log")
        ax.set_ylim(log_floor, upper)

    fig.subplots_adjust(left=0.08, right=0.995, bottom=0.12, top=0.92, wspace=0.18, hspace=0.30)
    return fig


def plot_blocking_retry_quantile_bands(
    inventory: pd.DataFrame,
    factor: str,
    *,
    retry_prefix: str = "blocked_retry_attempt",
    hours_per_bucket: float = 24.0,
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    scenario_records = _scenario_daily_retry_records(
        subset,
        retry_prefix=retry_prefix,
        hours_per_bucket=hours_per_bucket,
    )
    if not scenario_records:
        return None

    color_map = _scenario_color_map(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_records), base=7.2, per_extra=0.55), 4.6)
    )

    log_floor = 0.05
    ymax = log_floor
    for scenario_row, daily in scenario_records:
        scenario_key = str(scenario_row["scenario_key"])
        color = color_map[scenario_key]
        x = daily["day_index"]
        q25 = daily["retry_p25_mean"].clip(lower=log_floor)
        q50 = daily["retry_p50_mean"].clip(lower=log_floor)
        q75 = daily["retry_p75_mean"].clip(lower=log_floor)
        q99 = daily["retry_p99_mean"].clip(lower=log_floor)
        ymax = max(ymax, float(q99.max()))

        # Darker near the median, lighter farther into the upper tail.
        ax.fill_between(x, q25, q50, color=color, alpha=0.12, linewidth=0)
        ax.fill_between(x, q50, q75, color=color, alpha=0.12, linewidth=0)
        ax.fill_between(x, q75, q99, color=color, alpha=0.05, linewidth=0)
        ax.plot(
            x,
            q25,
            color=color,
            linewidth=1.0,
            alpha=0.55,
        )
        ax.plot(
            x,
            q50,
            color=color,
            linewidth=2.5,
            alpha=0.96,
            label=_scenario_plot_label(
                scenario_row,
                int(daily["episodes"].iloc[0]),
                short=True,
                include_episodes=False,
            ),
            marker=_marker_for_scenario(scenario_key),
            markersize=7.2,
            markerfacecolor="white",
            markeredgewidth=1.2,
        )
        ax.plot(
            x,
            q99,
            color=color,
            linewidth=1.3,
            alpha=0.80,
            linestyle="--",
        )

    ax.set_xlim(0.5, max(1.5, max(float(daily["day_index"].max()) for _, daily in scenario_records) + 0.5))
    ax.set_yscale("log")
    ax.set_ylim(1, max(1.0, ymax * 1.12))
    ax.set_xlabel("Day", fontsize=PAPER_AXIS_LABEL_SIZE)
    ax.set_ylabel("Client Retries (log)", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)
    ax.legend(
        loc="lower right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE - 1,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.5,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.12, right=0.995, bottom=0.22, top=0.94)
    return fig


def plot_malicious_proxy_offer_rate(
    path_or_locators: str | Path | Iterable[str | Path],
    *,
    hours_per_bucket: float = 1.0,
) -> matplotlib.figure.Figure | None:
    aggregated = aggregate_malicious_proxy_offer_rate_runs(
        path_or_locators,
        hours_per_bucket=hours_per_bucket,
    )
    if aggregated.empty:
        return None

    fig, ax = plt.subplots(figsize=(8.2, 4.3))
    series_specs = [
        ("combined_offer_rate_pct", "Combined", "#222222", "-", "o", 3.0),
        ("restricted_offer_rate_pct", "Restricted pool", "#e15759", "-", "s", 2.2),
        ("unrestricted_offer_rate_pct", "Unrestricted pool", "#4e79a7", "--", "^", 2.2),
    ]

    for column, label, color, linestyle, marker, linewidth in series_specs:
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start_mean"],
            aggregated[f"{column}_mean"],
            aggregated[f"{column}_std"],
            color=color,
            linewidth=linewidth,
            alpha=0.95,
            linestyle=linestyle,
            label=label,
            marker=marker,
            markersize=7.0,
            markerfacecolor="white",
            markeredgewidth=1.1,
            markevery=_markevery_for_series(aggregated["hours_since_start_mean"], target_markers=14),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.set_xlim(0.0, max(1.0, float(aggregated["hours_since_start_mean"].max() / 24.0)))
    upper = (
        aggregated["combined_offer_rate_pct_mean"] + aggregated["combined_offer_rate_pct_std"].fillna(0.0)
    ).max()
    ax.set_ylim(0.0, min(100.0, max(5.0, float(upper) * 1.08)))
    ax.set_xlabel("Day", fontsize=PAPER_AXIS_LABEL_SIZE)
    ax.set_ylabel("Offer Rate (%)", fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)
    ax.legend(
        loc="upper right",
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        borderpad=0.35,
        labelspacing=0.25,
        handlelength=1.5,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.14, right=0.995, bottom=0.23, top=0.94)
    return fig


CLIENT_NAT_PANELS = [
    ("unrestricted", "Unrestricted"),
    ("restricted", "Restricted"),
    ("unknown", "Unknown"),
]


def _scenario_records_for_nat_metric_plot(
    subset: pd.DataFrame,
    nat_metric_column: str,
) -> list[tuple[pd.Series, pd.DataFrame]]:
    scenario_records: list[tuple[pd.Series, pd.DataFrame]] = []
    for scenario_row, aggregated in _scenario_records_for_plot(subset):
        mean_col = f"{nat_metric_column}_mean"
        if mean_col not in aggregated.columns:
            continue
        filtered = aggregated.dropna(subset=[mean_col]).reset_index(drop=True)
        if filtered.empty:
            continue
        scenario_records.append((scenario_row, filtered))
    return scenario_records


def _plot_blocking_client_nat_metric_panels(
    inventory: pd.DataFrame,
    factor: str,
    *,
    nat_metric_suffix: str,
    ylabel: str,
    lower_clip: float | None = None,
    upper_clip: float | None = None,
    log_scale: bool = False,
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, factor, "blocking")
    if subset.empty:
        return None

    scenario_records_by_nat: dict[str, list[tuple[pd.Series, pd.DataFrame]]] = {}
    for nat_key, _ in CLIENT_NAT_PANELS:
        nat_metric_column = f"minute_{nat_key}_{nat_metric_suffix}"
        scenario_records_by_nat[nat_key] = _scenario_records_for_nat_metric_plot(subset, nat_metric_column)

    if not any(scenario_records_by_nat.values()):
        return None

    color_map = _scenario_color_map(subset)
    fig, axes = plt.subplots(1, len(CLIENT_NAT_PANELS), figsize=(15.2, 4.3), sharex=True)
    axes_arr = np.atleast_1d(axes)
    handles: list[object] = []
    labels: list[str] = []
    ymax = 0.0

    for ax, (nat_key, nat_label) in zip(axes_arr, CLIENT_NAT_PANELS):
        scenario_records = scenario_records_by_nat[nat_key]
        if not scenario_records:
            ax.set_title(nat_label, fontsize=PAPER_PANEL_TITLE_SIZE)
            ax.set_xlabel("Day", fontsize=PAPER_AXIS_LABEL_SIZE)
            ax.text(0.5, 0.5, "No data", transform=ax.transAxes, ha="center", va="center", fontsize=PAPER_TICK_LABEL_SIZE)
            style_paper_axes(ax)
            continue

        nat_metric_column = f"minute_{nat_key}_{nat_metric_suffix}"
        for row, aggregated in scenario_records:
            scenario_key = row["scenario_key"]
            is_baseline = scenario_key == BASELINE_KEYS["blocking"]
            label = _scenario_plot_label(
                row,
                int(aggregated["episodes"].iloc[0]),
                short=True,
                include_episodes=False,
            )
            mean = aggregated[f"{nat_metric_column}_mean"]
            std = aggregated.get(f"{nat_metric_column}_std", pd.Series(0.0, index=aggregated.index)).fillna(0.0)
            _plot_hours_series_with_band(
                ax,
                aggregated["hours_since_start"],
                mean,
                std,
                color=color_map[scenario_key],
                label=label,
                linewidth=2.9 if is_baseline else 2.2,
                alpha=0.96 if is_baseline else 0.92,
                marker=_marker_for_scenario(str(scenario_key)),
                markevery=_markevery_for_series(aggregated["hours_since_start"]),
                lower_clip=lower_clip,
                upper_clip=upper_clip,
            )
            ymax = max(ymax, float((mean + std).dropna().max()) if not (mean + std).dropna().empty else ymax)

        ax.set_title(nat_label, fontsize=PAPER_PANEL_TITLE_SIZE)
        _set_day_axis(ax, aggregated["hours_since_start"])
        if log_scale:
            ax.set_yscale("log")
        style_paper_axes(ax)

        panel_handles, panel_labels = ax.get_legend_handles_labels()
        if panel_handles and not handles:
            handles = panel_handles
            labels = panel_labels

    if upper_clip is not None:
        for ax in axes_arr:
            ax.set_ylim(0, upper_clip)
    elif not log_scale:
        upper = max(1.0, ymax * 1.08)
        for ax in axes_arr:
            ax.set_ylim(bottom=0.0, top=upper)
    elif log_scale:
        for ax in axes_arr:
            ax.set_ylim(bottom=max(0.01, lower_clip or 0.01))

    axes_arr[0].set_ylabel(ylabel, fontsize=PAPER_AXIS_LABEL_SIZE)
    if handles:
        fig.legend(
            handles,
            labels,
            loc="upper center",
            bbox_to_anchor=(0.5, 1.02),
            ncol=min(4, max(1, len(labels))),
            frameon=True,
            fontsize=PAPER_LEGEND_SIZE - 1,
        )
    fig.subplots_adjust(left=0.08, right=0.995, bottom=0.22, top=0.78, wspace=0.18)
    return fig


def plot_blocking_client_nat_attempt_rate_panels(
    inventory: pd.DataFrame,
    factor: str,
) -> matplotlib.figure.Figure | None:
    return _plot_blocking_client_nat_metric_panels(
        inventory,
        factor,
        nat_metric_suffix="blocked_retry_attempt_pct",
        ylabel="Attempts w/ >=1 Blocked Retry",
        lower_clip=0.0,
        upper_clip=100.0,
    )


def plot_blocking_client_nat_retry_band_panels(
    inventory: pd.DataFrame,
    factor: str,
) -> matplotlib.figure.Figure | None:
    return _plot_blocking_client_nat_metric_panels(
        inventory,
        factor,
        nat_metric_suffix="blocked_retry_avg_per_completed_attempt",
        ylabel="Blocked Retries / Completed Attempt",
        lower_clip=0.0,
        upper_clip=None,
    )


def plot_factor_delta_vs_default(
    inventory: pd.DataFrame,
    factor: str,
    mode: str,
    *,
    title_suffix: str = "",
    cumulative: bool = False,
) -> matplotlib.figure.Figure | None:
    baseline = _baseline_timeseries(inventory, mode)
    subset = _scenario_subset_without_baseline(inventory, factor, mode)
    if baseline.empty or subset.empty:
        return None

    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(["variant_order", "scenario_label"], ignore_index=True)
    scenario_panels: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_timeseries(records)
        delta = _delta_vs_baseline(
            aggregated,
            baseline,
            [column for column, _, _, _ in PROXY_CURVE_META],
        )
        if delta.empty:
            continue
        scenario_panels.append((scenario_row, delta))

    if not scenario_panels:
        return None

    transformed_panels: list[tuple[pd.Series, pd.Series, pd.Series, int]] = []
    all_delta_values = []
    for _, delta in scenario_panels:
        column = "coverage_total_pct"
        mean = delta[f"{column}_delta_mean"]
        std = delta[f"{column}_delta_std"]
        if cumulative:
            mean, std = _cumulative_series_from_band(delta["hours_since_start"], mean, std)
        transformed_panels.append(
            (
                delta["hours_since_start"],
                mean,
                std,
                int(delta["episodes_scenario"].iloc[0]),
            )
        )
        all_delta_values.extend(mean.dropna().tolist())
        all_delta_values.extend((mean + std).dropna().tolist())
        all_delta_values.extend((mean - std).dropna().tolist())
    y_limit = _symmetric_limit(all_delta_values, minimum=1.0)

    color_map = _scenario_color_map(subset)
    fig, ax = plt.subplots(
        figsize=(_compact_single_axis_width(len(scenario_panels), base=6.7, per_extra=0.5), 4.0)
    )
    for (scenario_row, _), (hours, mean, std, episodes_here) in zip(scenario_panels, transformed_panels):
        label = _scenario_plot_label(scenario_row, episodes_here, short=True)
        _plot_hours_series_with_band(
            ax,
            hours,
            mean,
            std,
            color=color_map[scenario_row["scenario_key"]],
            label=label,
            linewidth=2.8,
            alpha=0.94,
            marker=_marker_for_scenario(str(scenario_row["scenario_key"])),
            markevery=_markevery_for_series(hours),
        )
    ax.axhline(0, color="#555555", linewidth=1.0, linestyle="--", alpha=0.8)
    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.0, alpha=0.8)
    ax.set_ylim(-y_limit, y_limit)
    _set_day_axis(ax, transformed_panels[0][0])
    ylabel = "Cumulative total delta (pp-hours)" if cumulative else "Total delta vs default (pp)"
    ax.set_ylabel(ylabel, fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=max(1, len(labels)),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        columnspacing=1.0,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.11, right=0.995, bottom=0.23, top=0.82)
    return fig


def plot_factor_delta_by_proxy(
    inventory: pd.DataFrame,
    factor: str,
    mode: str,
    *,
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    baseline = _baseline_timeseries(inventory, mode)
    subset = _scenario_subset_without_baseline(inventory, factor, mode)
    if baseline.empty or subset.empty:
        return None

    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(["variant_order", "scenario_label"], ignore_index=True)
    scenario_deltas: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_timeseries(records)
        delta = _delta_vs_baseline(
            aggregated,
            baseline,
            [column for column, _, _, _ in PROXY_CURVE_META],
        )
        if delta.empty:
            continue
        scenario_deltas.append((scenario_row, delta))

    if not scenario_deltas:
        return None

    color_map = _scenario_color_map(subset)
    appendix_width = 18.8 + max(0, len(scenario_deltas) - 4) * 0.55
    fig, axes = plt.subplots(1, 4, figsize=(appendix_width, 4.0), sharex=True, sharey=True)

    all_delta_values = []
    for _, delta in scenario_deltas:
        for column, _, _, _ in PROXY_CURVE_META:
            all_delta_values.extend(delta[f"{column}_delta_mean"].dropna().tolist())
            all_delta_values.extend(
                (delta[f"{column}_delta_mean"] + delta[f"{column}_delta_std"]).dropna().tolist()
            )
            all_delta_values.extend(
                (delta[f"{column}_delta_mean"] - delta[f"{column}_delta_std"]).dropna().tolist()
            )
    max_abs_delta = max([abs(value) for value in all_delta_values], default=1.0)
    y_limit = max(1.0, min(100.0, np.ceil(max_abs_delta / 2.0) * 2.0))

    for ax, (column, panel_title, _, _) in zip(np.atleast_1d(axes).flatten(), PROXY_CURVE_META):
        for scenario_row, delta in scenario_deltas:
            episodes_here = int(delta["episodes_scenario"].iloc[0])
            label = _scenario_plot_label(scenario_row, episodes_here, short=True)
            _plot_hours_series_with_band(
                ax,
                delta["hours_since_start"],
                delta[f"{column}_delta_mean"],
                delta[f"{column}_delta_std"],
                color=color_map[scenario_row["scenario_key"]],
                label=label,
                linewidth=2.1,
                alpha=0.92,
                marker=_marker_for_scenario(str(scenario_row["scenario_key"])),
                markevery=_markevery_for_series(delta["hours_since_start"]),
            )
        ax.set_title(panel_title, fontsize=PAPER_PANEL_TITLE_SIZE)
        ax.axhline(0, color="#555555", linewidth=1.0, linestyle="--", alpha=0.8)
        ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.0, alpha=0.8)
        ax.set_ylim(-y_limit, y_limit)
        _set_day_axis(ax, delta["hours_since_start"])
        style_paper_axes(ax)

    axes[0].set_ylabel("Delta vs default (pp)", fontsize=PAPER_AXIS_LABEL_SIZE)

    handles, labels = np.atleast_1d(axes).flatten()[0].get_legend_handles_labels()
    dedup_handles = []
    dedup_labels = []
    for handle, label in zip(handles, labels):
        if label in dedup_labels:
            continue
        dedup_handles.append(handle)
        dedup_labels.append(label)
    fig.legend(
        dedup_handles,
        dedup_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=max(1, len(dedup_labels)),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
        columnspacing=1.0,
        handletextpad=0.5,
    )
    fig.subplots_adjust(left=0.055, right=0.995, bottom=0.23, top=0.76, wspace=0.08)
    return fig


def aggregate_scenario_hourly_diagnostics(records: pd.DataFrame) -> pd.DataFrame:
    if records.empty:
        return pd.DataFrame()

    hourly_rows = []
    for _, row in records.iterrows():
        df = parse_log_timeseries(row["locator"])
        if df.empty:
            continue

        working = df.copy()
        working["hour_bucket"] = np.floor(working["hours_since_start"]).astype(int)
        hourly = (
            working.groupby("hour_bucket", dropna=False)
            .agg(
                active_total=("active_total", "last"),
                coverage_total_pct=("coverage_total_pct", "last"),
                heap_never_seen_pct=("heap_never_seen_pct", "last"),
                unique_total=("unique_total", "last"),
                attacker_unique_total=("attacker_unique_total", "last"),
            )
            .reset_index()
        )
        if hourly.empty:
            continue

        hourly["hours_since_start"] = hourly["hour_bucket"].astype(float) + 1.0
        hourly["new_unique_total_per_hour"] = hourly["unique_total"].diff()
        hourly["new_attacker_unique_total_per_hour"] = hourly["attacker_unique_total"].diff()
        hourly.loc[hourly.index[0], "new_unique_total_per_hour"] = (
            hourly.loc[hourly.index[0], "unique_total"] - float(working["unique_total"].iloc[0])
        )
        hourly.loc[hourly.index[0], "new_attacker_unique_total_per_hour"] = (
            hourly.loc[hourly.index[0], "attacker_unique_total"]
            - float(working["attacker_unique_total"].iloc[0])
        )
        hourly["new_unique_total_per_hour"] = hourly["new_unique_total_per_hour"].clip(lower=0.0)
        hourly["new_attacker_unique_total_per_hour"] = hourly[
            "new_attacker_unique_total_per_hour"
        ].clip(lower=0.0)
        hourly["enumeration_gap_total_per_hour"] = (
            hourly["new_unique_total_per_hour"] - hourly["new_attacker_unique_total_per_hour"]
        )
        hourly["episode"] = row["episode"]
        hourly_rows.append(
            hourly[
                [
                    "hours_since_start",
                    "active_total",
                    "coverage_total_pct",
                    "heap_never_seen_pct",
                    "new_unique_total_per_hour",
                    "new_attacker_unique_total_per_hour",
                    "enumeration_gap_total_per_hour",
                    "episode",
                ]
            ]
        )

    if not hourly_rows:
        return pd.DataFrame()

    combined = pd.concat(hourly_rows, ignore_index=True)
    numeric_cols = [
        column
        for column in combined.select_dtypes(include=[np.number]).columns.tolist()
        if column != "hours_since_start"
    ]
    agg = (
        combined.groupby("hours_since_start", dropna=False)[numeric_cols]
        .agg(["mean", "std"])
        .reset_index()
    )
    agg.columns = [
        "hours_since_start"
        if column == ("hours_since_start", "")
        else f"{column[0]}_{column[1]}"
        for column in agg.columns.to_flat_index()
    ]
    std_cols = [col for col in agg.columns if col.endswith("_std")]
    agg[std_cols] = agg[std_cols].fillna(0.0)
    agg = agg.assign(episodes=len(hourly_rows))
    return agg.sort_values("hours_since_start", ignore_index=True)


def _scenario_records_for_hourly_diagnostics(
    subset: pd.DataFrame,
) -> list[tuple[pd.Series, pd.DataFrame]]:
    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    sort_cols = ["scenario_label"]
    if "baseline_order" in ordered.columns:
        sort_cols = ["baseline_order", "variant_order", "scenario_label"]
    elif "variant_order" in ordered.columns:
        sort_cols = ["variant_order", "scenario_label"]
    ordered = ordered.sort_values(sort_cols, ignore_index=True)

    scenario_records: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_hourly_diagnostics(records)
        if aggregated.empty:
            continue
        scenario_records.append((scenario_row, aggregated))
    return scenario_records


def aggregate_scenario_daily_retry_quantiles(
    records: pd.DataFrame,
    *,
    retry_prefix: str = "blocked_retry_attempt",
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    if records.empty:
        return pd.DataFrame()

    required_cols = [
        f"{retry_prefix}_p25",
        f"{retry_prefix}_p50",
        f"{retry_prefix}_p75",
        f"{retry_prefix}_p99",
    ]
    daily_rows = []
    for _, row in records.iterrows():
        df = parse_log_timeseries(row["locator"])
        if df.empty or any(column not in df.columns for column in required_cols):
            continue

        working = (
            df[["hours_since_start", *required_cols]]
            .dropna(subset=["hours_since_start"])
            .sort_values("hours_since_start")
            .copy()
        )
        if working.empty:
            continue
        working["day_index"] = np.floor(working["hours_since_start"] / hours_per_bucket).astype(int) + 1
        daily = (
            working.groupby("day_index", dropna=False)
            .agg(
                hours_since_start=("hours_since_start", "last"),
                retry_p25=(f"{retry_prefix}_p25", "last"),
                retry_p50=(f"{retry_prefix}_p50", "last"),
                retry_p75=(f"{retry_prefix}_p75", "last"),
                retry_p99=(f"{retry_prefix}_p99", "last"),
            )
            .reset_index()
        )
        daily["episode"] = row["episode"]
        daily_rows.append(daily)

    if not daily_rows:
        return pd.DataFrame()

    combined = pd.concat(daily_rows, ignore_index=True)
    agg = (
        combined.groupby("day_index", dropna=False)[
            ["hours_since_start", "retry_p25", "retry_p50", "retry_p75", "retry_p99"]
        ]
        .agg(["mean", "std"])
        .reset_index()
    )
    agg.columns = [
        "day_index"
        if column == ("day_index", "")
        else f"{column[0]}_{column[1]}"
        for column in agg.columns.to_flat_index()
    ]
    std_cols = [col for col in agg.columns if col.endswith("_std")]
    agg[std_cols] = agg[std_cols].fillna(0.0)
    agg = agg.assign(episodes=len(daily_rows))
    return agg.sort_values("day_index", ignore_index=True)


def aggregate_scenario_daily_request_harm(
    records: pd.DataFrame,
    *,
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    if records.empty:
        return pd.DataFrame()

    cumulative_cols = [
        "matches_total",
        "retry_limit_hits",
        "total_retry_events",
        "client_nomatch_blocked",
        "client_nomatch_no_proxies",
        "client_nomatch_timed_out",
        "client_nomatch_other",
    ]
    daily_rows = []
    for _, row in records.iterrows():
        df = parse_log_timeseries(row["locator"])
        if df.empty or any(column not in df.columns for column in cumulative_cols):
            continue

        working = df.copy()
        working["day_index"] = np.floor(working["hours_since_start"] / hours_per_bucket).astype(int) + 1
        daily = (
            working.groupby("day_index", dropna=False)
            .agg(
                hours_since_start=("hours_since_start", "max"),
                matches_total=("matches_total", "last"),
                retry_limit_hits=("retry_limit_hits", "last"),
                total_retry_events=("total_retry_events", "last"),
                client_nomatch_blocked=("client_nomatch_blocked", "last"),
                client_nomatch_no_proxies=("client_nomatch_no_proxies", "last"),
                client_nomatch_timed_out=("client_nomatch_timed_out", "last"),
                client_nomatch_other=("client_nomatch_other", "last"),
            )
            .reset_index()
        )
        if daily.empty:
            continue

        for column in cumulative_cols:
            delta_col = f"delta_{column}"
            daily[delta_col] = daily[column].diff()
            daily[delta_col] = daily[delta_col].fillna(daily[column]).clip(lower=0.0)

        daily["delta_total_requests"] = (
            daily["delta_matches_total"] + daily["delta_total_retry_events"]
        )
        daily["delta_completed_attempts_total"] = (
            daily["delta_matches_total"] + daily["delta_retry_limit_hits"]
        )
        daily["delta_unsuccessful_request_rate_pct"] = np.where(
            daily["delta_total_requests"] > 0,
            100.0 * daily["delta_total_retry_events"] / daily["delta_total_requests"],
            np.nan,
        )
        daily["delta_success_request_rate_pct"] = np.where(
            daily["delta_total_requests"] > 0,
            100.0 * daily["delta_matches_total"] / daily["delta_total_requests"],
            np.nan,
        )
        for suffix in ("blocked", "no_proxies", "timed_out", "other"):
            delta_col = f"delta_client_nomatch_{suffix}"
            rate_col = f"delta_{suffix}_request_rate_pct"
            daily[rate_col] = np.where(
                daily["delta_total_requests"] > 0,
                100.0 * daily[delta_col] / daily["delta_total_requests"],
                np.nan,
            )

        daily["delta_retry_events_per_success"] = np.where(
            daily["delta_matches_total"] > 0,
            daily["delta_total_retry_events"] / daily["delta_matches_total"],
            np.nan,
        )
        daily["delta_retry_events_per_completed_attempt"] = np.where(
            daily["delta_completed_attempts_total"] > 0,
            daily["delta_total_retry_events"] / daily["delta_completed_attempts_total"],
            np.nan,
        )
        daily["episode"] = row["episode"]
        daily_rows.append(
            daily[
                [
                    "day_index",
                    "hours_since_start",
                    "delta_total_requests",
                    "delta_completed_attempts_total",
                    "delta_unsuccessful_request_rate_pct",
                    "delta_success_request_rate_pct",
                    "delta_blocked_request_rate_pct",
                    "delta_no_proxies_request_rate_pct",
                    "delta_timed_out_request_rate_pct",
                    "delta_other_request_rate_pct",
                    "delta_retry_events_per_success",
                    "delta_retry_events_per_completed_attempt",
                    "episode",
                ]
            ]
        )

    if not daily_rows:
        return pd.DataFrame()

    combined = pd.concat(daily_rows, ignore_index=True)
    numeric_cols = [
        column
        for column in combined.select_dtypes(include=[np.number]).columns.tolist()
        if column != "day_index"
    ]
    agg = (
        combined.groupby("day_index", dropna=False)[numeric_cols]
        .agg(["mean", "std"])
        .reset_index()
    )
    agg.columns = [
        "day_index"
        if column == ("day_index", "")
        else f"{column[0]}_{column[1]}"
        for column in agg.columns.to_flat_index()
    ]
    std_cols = [col for col in agg.columns if col.endswith("_std")]
    agg[std_cols] = agg[std_cols].fillna(0.0)
    agg = agg.assign(episodes=len(daily_rows))
    return agg.sort_values("day_index", ignore_index=True)


def _scenario_daily_retry_records(
    subset: pd.DataFrame,
    *,
    retry_prefix: str = "blocked_retry_attempt",
    hours_per_bucket: float = 24.0,
) -> list[tuple[pd.Series, pd.DataFrame]]:
    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(
        ["baseline_order", "variant_order", "scenario_label"],
        ignore_index=True,
    )

    scenario_records: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_daily_retry_quantiles(
            records,
            retry_prefix=retry_prefix,
            hours_per_bucket=hours_per_bucket,
        )
        if aggregated.empty:
            continue
        scenario_records.append((scenario_row, aggregated))
    return scenario_records


def _scenario_daily_request_harm_records(
    subset: pd.DataFrame,
    *,
    hours_per_bucket: float = 24.0,
) -> list[tuple[pd.Series, pd.DataFrame]]:
    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(
        ["baseline_order", "variant_order", "scenario_label"],
        ignore_index=True,
    )

    scenario_records: list[tuple[pd.Series, pd.DataFrame]] = []
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_daily_request_harm(
            records,
            hours_per_bucket=hours_per_bucket,
        )
        if aggregated.empty:
            continue
        scenario_records.append((scenario_row, aggregated))
    return scenario_records


def _plot_series_with_band(
    ax: matplotlib.axes.Axes,
    x: pd.Series,
    mean: pd.Series,
    std: pd.Series,
    *,
    color: str,
    label: str,
    linewidth: float,
    alpha: float,
    linestyle: str = "-",
    marker: str | None = None,
    markersize: float = 6.8,
    markevery: int | None = None,
    markerfacecolor: str = "white",
    markeredgewidth: float = 1.2,
    lower_clip: float | None = None,
    upper_clip: float | None = None,
) -> None:
    ax.plot(
        x,
        mean,
        color=color,
        label=label,
        linewidth=linewidth,
        alpha=alpha,
        linestyle=linestyle,
        marker=marker,
        markersize=markersize if marker else None,
        markevery=markevery if marker else None,
        markerfacecolor=markerfacecolor if marker else None,
        markeredgecolor=color if marker else None,
        markeredgewidth=markeredgewidth if marker else None,
    )
    if std.fillna(0.0).eq(0.0).all():
        return
    lower = mean - std
    upper = mean + std
    if lower_clip is not None:
        lower = lower.clip(lower=lower_clip)
        upper = upper.clip(lower=lower_clip)
    if upper_clip is not None:
        lower = lower.clip(upper=upper_clip)
        upper = upper.clip(upper=upper_clip)
    ax.fill_between(x, lower, upper, color=color, alpha=0.10, linewidth=0)


def _symmetric_limit(values: list[float], *, minimum: float = 1.0) -> float:
    finite = [abs(value) for value in values if np.isfinite(value)]
    if not finite:
        return minimum
    max_abs = max(finite)
    if max_abs <= minimum:
        return minimum
    order = 10 ** np.floor(np.log10(max_abs))
    step = max(order / 2.0, minimum / 2.0)
    return float(np.ceil(max_abs / step) * step)


def plot_churn_created_vs_learned(
    inventory: pd.DataFrame,
    *,
    mode: str = "enumeration",
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, "Churn Rate", mode)
    if subset.empty:
        return None

    scenario_records = _scenario_records_for_hourly_diagnostics(subset)
    if not scenario_records:
        return None
    color_map = _scenario_color_map(subset)
    fig, axes = plt.subplots(1, 2, figsize=(11.8, 4.2), sharex=True, sharey=True)
    panel_meta = [
        ("new_unique_total_per_hour", "New Proxies Created per Hour"),
        ("new_attacker_unique_total_per_hour", "New Proxies Learned per Hour"),
    ]

    for ax, (column, panel_title) in zip(axes, panel_meta):
        for row, aggregated in scenario_records:
            scenario_key = row["scenario_key"]
            is_baseline = scenario_key == BASELINE_KEYS[mode]
            label = row["scenario_label"]
            episodes_here = int(aggregated["episodes"].iloc[0])
            if episodes_here > 1:
                label = f"{label} (n={episodes_here})"
            _plot_hours_series_with_band(
                ax,
                aggregated["hours_since_start"],
                aggregated[f"{column}_mean"],
                aggregated[f"{column}_std"],
                color=color_map[scenario_key],
                label=label,
                linewidth=2.8 if is_baseline else 2.1,
                alpha=0.95 if is_baseline else 0.90,
                marker=_marker_for_scenario(str(scenario_key)),
                markevery=_markevery_for_series(aggregated["hours_since_start"]),
                lower_clip=0.0,
            )
        ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
        ax.set_title(panel_title, fontsize=PAPER_PANEL_TITLE_SIZE)
        _set_day_axis(ax, aggregated["hours_since_start"])
        ax.set_ylabel("Proxies per hour", fontsize=PAPER_AXIS_LABEL_SIZE)
        style_paper_axes(ax)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=min(3, max(1, len(labels))),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
    )
    fig.subplots_adjust(left=0.08, right=0.995, bottom=0.22, top=0.84, wspace=0.16)
    return fig


def plot_churn_delta_diagnostics(
    inventory: pd.DataFrame,
    *,
    mode: str = "enumeration",
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    baseline_rows = inventory[
        (inventory["scenario_key"] == BASELINE_KEYS[mode]) & (inventory["mode"] == mode)
    ].copy()
    subset = _scenario_subset_without_baseline(inventory, "Churn Rate", mode)
    if baseline_rows.empty or subset.empty:
        return None

    baseline = aggregate_scenario_hourly_diagnostics(baseline_rows)
    if baseline.empty:
        return None

    ordered = subset.drop_duplicates(subset=["scenario_key"]).copy()
    ordered = ordered.sort_values(["variant_order", "scenario_label"], ignore_index=True)
    color_map = _scenario_color_map(
        pd.concat([baseline_rows, subset], ignore_index=True).drop_duplicates(
            subset=["scenario_key", "mode", "episode"]
        )
    )
    scenario_deltas: list[tuple[pd.Series, pd.DataFrame]] = []
    delta_columns = [
        "coverage_total_pct",
        "active_total",
        "new_unique_total_per_hour",
        "new_attacker_unique_total_per_hour",
    ]
    for _, scenario_row in ordered.iterrows():
        records = subset[subset["scenario_key"] == scenario_row["scenario_key"]].copy()
        aggregated = aggregate_scenario_hourly_diagnostics(records)
        delta = _delta_vs_baseline(aggregated, baseline, delta_columns)
        if delta.empty:
            continue
        scenario_deltas.append((scenario_row, delta))

    if not scenario_deltas:
        return None

    fig, axes = plt.subplots(2, 2, figsize=(11.8, 6.8), sharex=True)
    panel_meta = [
        ("coverage_total_pct", "Coverage Delta vs Default", "Delta (pp)"),
        ("active_total", "Active Proxies Delta vs Default", "Delta proxies"),
        ("new_unique_total_per_hour", "New Proxies Created per Hour", "Delta proxies per hour"),
        (
            "new_attacker_unique_total_per_hour",
            "New Proxies Learned per Hour",
            "Delta proxies per hour",
        ),
    ]

    for ax, (column, panel_title, ylabel) in zip(axes.flat, panel_meta):
        panel_values = []
        for row, delta in scenario_deltas:
            label = row["scenario_label"]
            episodes_here = int(delta["episodes_scenario"].iloc[0])
            if episodes_here > 1:
                label = f"{label} (n={episodes_here})"
            _plot_hours_series_with_band(
                ax,
                delta["hours_since_start"],
                delta[f"{column}_delta_mean"],
                delta[f"{column}_delta_std"],
                color=color_map[row["scenario_key"]],
                label=label,
                linewidth=2.1,
                alpha=0.92,
                marker=_marker_for_scenario(str(row["scenario_key"])),
                markevery=_markevery_for_series(delta["hours_since_start"]),
            )
            panel_values.extend(delta[f"{column}_delta_mean"].dropna().tolist())
            panel_values.extend(
                (delta[f"{column}_delta_mean"] + delta[f"{column}_delta_std"]).dropna().tolist()
            )
            panel_values.extend(
                (delta[f"{column}_delta_mean"] - delta[f"{column}_delta_std"]).dropna().tolist()
            )
        y_limit = _symmetric_limit(panel_values, minimum=1.0 if "pct" in column else 100.0)
        ax.axhline(0, color="#555555", linewidth=1.0, linestyle="--", alpha=0.8)
        ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.0, alpha=0.8)
        ax.set_title(panel_title, fontsize=PAPER_PANEL_TITLE_SIZE)
        ax.set_ylabel(ylabel, fontsize=PAPER_AXIS_LABEL_SIZE)
        ax.set_ylim(-y_limit, y_limit)
        _set_day_axis(ax, delta["hours_since_start"])
        style_paper_axes(ax)

    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=min(4, max(1, len(labels))),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
    )
    fig.subplots_adjust(left=0.10, right=0.995, bottom=0.16, top=0.90, wspace=0.24, hspace=0.26)
    return fig


def plot_churn_heap_unseen(
    inventory: pd.DataFrame,
    *,
    mode: str = "enumeration",
    title_suffix: str = "",
) -> matplotlib.figure.Figure | None:
    subset = _subset_for_factor(inventory, "Churn Rate", mode)
    if subset.empty:
        return None

    scenario_records = _scenario_records_for_plot(subset)
    if not scenario_records:
        return None
    color_map = _scenario_color_map(subset)
    fig, ax = plt.subplots(figsize=(9.8, 4.2))

    for row, aggregated in scenario_records:
        scenario_key = row["scenario_key"]
        is_baseline = scenario_key == BASELINE_KEYS[mode]
        label = row["scenario_label"]
        episodes_here = int(aggregated["episodes"].iloc[0])
        if episodes_here > 1:
            label = f"{label} (n={episodes_here})"
        _plot_hours_series_with_band(
            ax,
            aggregated["hours_since_start"],
            aggregated["heap_never_seen_pct_mean"],
            aggregated["heap_never_seen_pct_std"],
            color=color_map[scenario_key],
            label=label,
            linewidth=2.8 if is_baseline else 2.1,
            alpha=0.95 if is_baseline else 0.90,
            marker=_marker_for_scenario(str(scenario_key)),
            markevery=_markevery_for_series(aggregated["hours_since_start"]),
            lower_clip=0.0,
            upper_clip=100.0,
        )

    ax.axvline(PROBER_START_HOURS / 24.0, color="#555555", linestyle=":", linewidth=1.2, alpha=0.8)
    _set_day_axis(ax, aggregated["hours_since_start"])
    ax.set_ylabel("Heap never seen (%)", fontsize=PAPER_AXIS_LABEL_SIZE)
    ax.set_ylim(0, 100)
    style_paper_axes(ax)
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.01),
        ncol=min(3, max(1, len(labels))),
        frameon=True,
        fontsize=PAPER_LEGEND_SIZE,
    )
    fig.subplots_adjust(left=0.11, right=0.995, bottom=0.22, top=0.84)
    return fig


def generate_churn_diagnostic_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
    *,
    mode: str = "enumeration",
) -> pd.DataFrame:
    specs = [
        ("created_vs_learned", "created-vs-learned", plot_churn_created_vs_learned),
        ("delta_diagnostics", "delta-diagnostics", plot_churn_delta_diagnostics),
        ("heap_unseen", "heap-unseen", plot_churn_heap_unseen),
    ]
    rows = []
    for label, filename_suffix, plotter in specs:
        fig = plotter(inventory, mode=mode)
        if fig is None:
            continue
        filename = f"{mode}-churn-{filename_suffix}.pdf"
        saved_to = save_paper_figure(fig, out_dir, filename)
        rows.append(
            {
                "mode": mode,
                "figure": label,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def estimate_churn_keepup_thresholds(
    inventory: pd.DataFrame,
    *,
    mode: str = "enumeration",
    steady_state_start_hour: float = 336.0,
    steady_state_end_hour: float = 696.0,
    practical_keepup_ratio: float = 0.95,
    prober_interval_seconds: float = 1.0,
) -> dict[str, object]:
    subset = inventory[(inventory["factor"] == "Churn Rate") & (inventory["mode"] == mode)].copy()
    baseline_rows = inventory[
        (inventory["scenario_key"] == BASELINE_KEYS[mode]) & (inventory["mode"] == mode)
    ].copy()
    if subset.empty or baseline_rows.empty:
        return {
            "observed": pd.DataFrame(),
            "thresholds": pd.DataFrame(),
        }

    subset = pd.concat([baseline_rows, subset], ignore_index=True)
    subset = subset.drop_duplicates(subset=["scenario_key", "episode"]).copy()

    observed_rows = []
    for scenario_key, multiplier in CHURN_SCENARIO_MULTIPLIERS.items():
        records = subset[subset["scenario_key"] == scenario_key].copy()
        if records.empty:
            continue
        aggregated = aggregate_scenario_timeseries(records)
        if aggregated.empty:
            continue
        steady = aggregated[
            (aggregated["hours_since_start"] >= steady_state_start_hour)
            & (aggregated["hours_since_start"] <= steady_state_end_hour)
        ].copy()
        if len(steady) < 2:
            steady = aggregated[aggregated["hours_since_start"] >= PROBER_START_HOURS].copy()
        if len(steady) < 2:
            continue
        duration_hours = float(steady["hours_since_start"].iloc[-1] - steady["hours_since_start"].iloc[0])
        if duration_hours <= 0:
            continue
        created_per_hour = float(
            (steady["unique_total_mean"].iloc[-1] - steady["unique_total_mean"].iloc[0]) / duration_hours
        )
        learned_per_hour = float(
            (
                steady["attacker_unique_total_mean"].iloc[-1]
                - steady["attacker_unique_total_mean"].iloc[0]
            )
            / duration_hours
        )
        active_total_mean = float(steady["active_total_mean"].mean())
        attacker_count = float(records["attackers"].mean())
        observed_rows.append(
            {
                "scenario_key": scenario_key,
                "scenario_label": str(records.iloc[0]["scenario_label"]),
                "configured_churn_multiplier": multiplier,
                "attackers_mean": attacker_count,
                "steady_created_per_hour": created_per_hour,
                "steady_learned_per_hour": learned_per_hour,
                "steady_learned_ratio": learned_per_hour / created_per_hour if created_per_hour > 0 else np.nan,
                "steady_created_pct_active_per_hour": (
                    created_per_hour / active_total_mean if active_total_mean > 0 else np.nan
                ),
                "steady_learned_pct_active_per_hour": (
                    learned_per_hour / active_total_mean if active_total_mean > 0 else np.nan
                ),
                "steady_new_unique_per_prober_poll": (
                    learned_per_hour / (attacker_count * (3600.0 / prober_interval_seconds))
                    if attacker_count > 0 and prober_interval_seconds > 0
                    else np.nan
                ),
                "steady_final_coverage_pct": float(aggregated["coverage_total_pct_mean"].iloc[-1]),
                "steady_active_total_mean": active_total_mean,
            }
        )

    observed = pd.DataFrame(observed_rows).sort_values(
        "configured_churn_multiplier",
        ignore_index=True,
    )
    if len(observed) < 2:
        return {
            "observed": observed,
            "thresholds": pd.DataFrame(),
        }

    x = observed["configured_churn_multiplier"].to_numpy(dtype=float)
    y_created = observed["steady_created_per_hour"].to_numpy(dtype=float)
    y_ratio = observed["steady_learned_ratio"].to_numpy(dtype=float)
    created_fit = np.polyfit(x, y_created, deg=1)
    ratio_fit = np.polyfit(y_created, y_ratio, deg=1)
    created_intercept, created_slope = float(created_fit[1]), float(created_fit[0])
    ratio_intercept, ratio_slope = float(ratio_fit[1]), float(ratio_fit[0])

    attacker_count_mean = float(observed["attackers_mean"].mean())
    hard_ceiling_births_per_hour = (
        attacker_count_mean * (3600.0 / prober_interval_seconds)
        if attacker_count_mean > 0 and prober_interval_seconds > 0
        else np.nan
    )
    mean_active_total = float(observed["steady_active_total_mean"].mean())

    practical_births_per_hour = np.nan
    practical_multiplier = np.nan
    practical_pct_active = np.nan
    if ratio_slope < 0:
        practical_births_per_hour = float((practical_keepup_ratio - ratio_intercept) / ratio_slope)
        if created_slope != 0:
            practical_multiplier = float((practical_births_per_hour - created_intercept) / created_slope)
        if mean_active_total > 0:
            practical_pct_active = float(practical_births_per_hour / mean_active_total)

    hard_multiplier = np.nan
    hard_pct_active = np.nan
    if created_slope != 0 and np.isfinite(hard_ceiling_births_per_hour):
        hard_multiplier = float((hard_ceiling_births_per_hour - created_intercept) / created_slope)
    if mean_active_total > 0 and np.isfinite(hard_ceiling_births_per_hour):
        hard_pct_active = float(hard_ceiling_births_per_hour / mean_active_total)

    thresholds = pd.DataFrame(
        [
            {
                "mode": mode,
                "steady_state_window_hours": f"{int(steady_state_start_hour)}-{int(steady_state_end_hour)}",
                "practical_keepup_ratio_target": practical_keepup_ratio,
                "attackers_mean": attacker_count_mean,
                "prober_interval_seconds": prober_interval_seconds,
                "mean_active_total": mean_active_total,
                "created_fit_intercept": created_intercept,
                "created_fit_slope_per_multiplier": created_slope,
                "ratio_fit_intercept": ratio_intercept,
                "ratio_fit_slope_per_birth_per_hour": ratio_slope,
                "practical_threshold_births_per_hour": practical_births_per_hour,
                "practical_threshold_pct_active_per_hour": practical_pct_active,
                "practical_threshold_configured_churn_multiplier": practical_multiplier,
                "hard_ceiling_births_per_hour": hard_ceiling_births_per_hour,
                "hard_ceiling_pct_active_per_hour": hard_pct_active,
                "hard_ceiling_configured_churn_multiplier": hard_multiplier,
            }
        ]
    )
    return {
        "observed": observed,
        "thresholds": thresholds,
    }


def plot_metric_bars(
    summary: pd.DataFrame,
    mode: str,
    metric: str,
    xlabel: str,
    *,
    sort_by_metric: bool = False,
) -> matplotlib.figure.Figure | None:
    subset = summary[summary["mode"] == mode].copy()
    if subset.empty:
        return None
    if sort_by_metric:
        subset = subset.sort_values(metric, ascending=True, ignore_index=True)
    else:
        subset = subset.sort_values(
            ["factor_order", "variant_order", "scenario_label"],
            ignore_index=True,
        )
    labels = [
        row["scenario_label"]
        if row["factor"] == "Baseline"
        else f"{row['factor']}: {row['scenario_label']}"
        for _, row in subset.iterrows()
    ]
    colors = [FACTOR_COLORS.get(factor, "#7f7f7f") for factor in subset["factor"]]
    fig_height = max(4.5, 0.45 * len(subset))
    fig, ax = plt.subplots(figsize=(10.5, fig_height))
    ax.barh(range(len(subset)), subset[metric], color=colors, alpha=0.9)
    ax.set_yticks(range(len(subset)))
    ax.set_yticklabels(labels)
    ax.set_xlabel(xlabel, fontsize=PAPER_AXIS_LABEL_SIZE)
    style_paper_axes(ax)
    baseline_key = BASELINE_KEYS[mode]
    baseline_rows = subset[subset["scenario_key"] == baseline_key]
    if not baseline_rows.empty:
        ax.axvline(
            float(baseline_rows.iloc[0][metric]),
            color="#222222",
            linestyle="--",
            linewidth=1.4,
            alpha=0.9,
        )
    plt.tight_layout()
    return fig


def available_factors(
    inventory: pd.DataFrame,
    mode: str,
    *,
    include_miscellaneous: bool = False,
) -> list[str]:
    subset = inventory[inventory["mode"] == mode]
    if subset.empty:
        return []
    factor_frame = subset[subset["factor"] != "Baseline"][["factor", "factor_order"]].drop_duplicates()
    if not include_miscellaneous:
        factor_frame = factor_frame[factor_frame["factor"] != "Miscellaneous"].copy()
    factor_frame = factor_frame.sort_values(["factor_order", "factor"])
    return list(factor_frame["factor"])


def available_factors_with_baseline(
    inventory: pd.DataFrame,
    mode: str,
    *,
    include_miscellaneous: bool = False,
) -> list[str]:
    factors = available_factors(inventory, mode, include_miscellaneous=include_miscellaneous)
    baseline_present = not inventory[
        (inventory["scenario_key"] == BASELINE_KEYS[mode]) & (inventory["mode"] == mode)
    ].empty
    return (["Baseline"] if baseline_present else []) + factors


def generate_factor_figures(
    inventory: pd.DataFrame,
    mode: str,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors(inventory, mode):
        if mode == "enumeration":
            fig = plot_factor_enumeration(inventory, factor)
        else:
            fig = plot_factor_blocking(inventory, factor)
        if fig is None:
            continue
        filename = f"{mode}-{normalize_name(factor)}.pdf"
        saved_to = save_paper_figure(fig, out_dir, filename)
        rows.append(
            {
                "mode": mode,
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_delta_factor_figures(
    inventory: pd.DataFrame,
    mode: str,
    out_dir: Path,
    *,
    cumulative: bool = False,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors(inventory, mode):
        fig = plot_factor_delta_vs_default(inventory, factor, mode, cumulative=cumulative)
        if fig is None:
            continue
        suffix = "-cumulative" if cumulative else ""
        filename = f"{mode}-delta-vs-default{suffix}-{normalize_name(factor)}.pdf"
        saved_to = save_paper_figure(fig, out_dir, filename)
        rows.append(
            {
                "mode": mode,
                "factor": factor,
                "figure_path": str(saved_to),
                "cumulative": cumulative,
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_enumeration_total_only_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "enumeration"):
        fig = plot_factor_enumeration_total_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(fig, out_dir, f"enumeration-total-only-{filename_key}.pdf")
        rows.append(
            {
                "mode": "enumeration",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_active_heap_seen_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "enumeration"):
        fig = plot_factor_active_heap_seen_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"enumeration-active-heap-seen-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "enumeration",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_retry_only_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_retry_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(fig, out_dir, f"blocking-retries-only-{filename_key}.pdf")
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_blocked_attempt_rate_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_blocked_attempt_rate_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-blocked-attempt-rate-only-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_unsuccessful_request_rate_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_unsuccessful_request_rate_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-unsuccessful-request-rate-only-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_daily_unsuccessful_request_rate_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
    *,
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_daily_unsuccessful_request_rate_only(
            inventory,
            factor,
            hours_per_bucket=hours_per_bucket,
        )
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-daily-unsuccessful-request-rate-only-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_daily_retry_cost_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
    *,
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_daily_retry_cost_only(
            inventory,
            factor,
            hours_per_bucket=hours_per_bucket,
        )
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-daily-retries-per-completed-attempt-only-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_enumeration_proxy_coverage_appendix_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "enumeration"):
        if factor == "Baseline":
            fig = plot_enumeration_baseline_proxy_overlay(inventory)
        else:
            fig = plot_factor_enumeration(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"enumeration-appendix-proxy-coverage-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "enumeration",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_retry_appendix_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_retry_only(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-appendix-retries-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_nomatch_reason_appendix_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_factor_blocking_nomatch_reason_panels(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-appendix-fail-reasons-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
                "figure_family": "no_match_reason_shares",
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_retry_quantile_band_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
    *,
    retry_prefix: str = "blocked_retry_attempt",
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_blocking_retry_quantile_bands(
            inventory,
            factor,
            retry_prefix=retry_prefix,
            hours_per_bucket=hours_per_bucket,
        )
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-retry-distribution-quantile-bands-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_total_retry_quantile_band_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
    *,
    hours_per_bucket: float = 24.0,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_blocking_retry_quantile_bands(
            inventory,
            factor,
            retry_prefix="total_retry_attempt",
            hours_per_bucket=hours_per_bucket,
        )
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-total-retry-distribution-quantile-bands-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_client_nat_attempt_rate_appendix_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_blocking_client_nat_attempt_rate_panels(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-appendix-client-nat-attempt-rate-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
                "figure_family": "client_nat_attempt_rate",
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_blocking_client_nat_retry_band_appendix_figures(
    inventory: pd.DataFrame,
    out_dir: Path,
) -> pd.DataFrame:
    rows = []
    for factor in available_factors_with_baseline(inventory, "blocking"):
        fig = plot_blocking_client_nat_retry_band_panels(inventory, factor)
        if fig is None:
            continue
        filename_key = "default" if factor == "Baseline" else normalize_name(factor)
        saved_to = save_paper_figure(
            fig,
            out_dir,
            f"blocking-appendix-client-nat-retry-bands-{filename_key}.pdf",
        )
        rows.append(
            {
                "mode": "blocking",
                "factor": factor,
                "figure_path": str(saved_to),
                "figure_family": "client_nat_retry_bands",
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)


def generate_delta_by_proxy_figures(
    inventory: pd.DataFrame,
    mode: str,
    out_dir: Path,
    *,
    factors: list[str] | None = None,
) -> pd.DataFrame:
    rows = []
    target_factors = factors or available_factors(inventory, mode)
    for factor in target_factors:
        fig = plot_factor_delta_by_proxy(inventory, factor, mode)
        if fig is None:
            continue
        filename = f"{mode}-delta-vs-default-by-proxy-{normalize_name(factor)}.pdf"
        saved_to = save_paper_figure(fig, out_dir, filename)
        rows.append(
            {
                "mode": mode,
                "factor": factor,
                "figure_path": str(saved_to),
            }
        )
        plt.close(fig)
    return pd.DataFrame(rows)
