"""
Phase 3, Step 3 — synthetic log generator (scale testing).

Builds a CSV in the project's own log schema (``timestamp, source, event_type,
actor, target, metadata``) with an exact number of events, so performance work
can be measured on a known, reproducible workload instead of on whichever
real dataset happens to be on disk.

The log is benign background noise plus a few injected attack chains:

* Noise never satisfies a rule on its own: registry writes hit non-autostart
  keys, network connections use well-known ports, nothing is PowerShell or a
  log clear.
* Each chain (on its own host) is the same story as ``attack_sample.csv``:
  process -> autostart registry write -> PowerShell -> download -> beacon on a
  non-standard port -> log clear. Every detection therefore involves at least
  one chain event, which makes a regression in either speed or detection
  visible. (A rule can pair a chain event with nearby noise, so the number of
  conclusions can exceed the number of chains.)

Same ``seed`` and arguments always produce the same file.

Usage:
    python -m app.synthetic out.csv --events 10000 --chains 3 --seed 7
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

COLUMNS = ["timestamp", "source", "event_type", "actor", "target", "metadata"]

# Events in one injected attack chain (see _chain_rows).
CHAIN_LENGTH = 7

_START = datetime(2024, 1, 1, 8, 0, 0, tzinfo=UTC)

_NOISE_PROCESSES = [
    "explorer.exe",
    "chrome.exe",
    "notepad.exe",
    "outlook.exe",
    "calc.exe",
    "code.exe",
    "teams.exe",
]
_NOISE_PORTS = [80, 443, 53]
_RUN_KEY = r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Updater"


def _meta(**values: Any) -> str:
    return json.dumps(values, sort_keys=True)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain_rows(host: str, start: datetime, pid_base: int) -> list[dict[str, str]]:
    """The attack story, one row per step, a few seconds apart."""
    steps: list[tuple[str, str, str, str]] = [
        (
            "process_execution",
            "USER01",
            "invoice.exe",
            _meta(pid=pid_base, parentpid=1),
        ),
        (
            "registry_modification",
            "USER01",
            _RUN_KEY,
            _meta(value="C:\\temp\\invoice.exe"),
        ),
        (
            "powershell_execution",
            "USER01",
            "powershell.exe",
            _meta(scriptblock="Set-MpPreference -DisableRealtimeMonitoring $true"),
        ),
        (
            "file_download",
            "USER01",
            "C:\\temp\\stage2.ps1",
            _meta(url="http://malicious.example/stage2.ps1"),
        ),
        (
            "network_connection",
            "invoice.exe",
            "185.220.101.1",
            _meta(DestinationPort=4444),
        ),
        ("log_deletion", "USER01", "Security.evtx", _meta(method="wevtutil cl")),
        ("file_creation", "USER01", "C:\\temp\\out.txt", _meta()),
    ]
    assert len(steps) == CHAIN_LENGTH
    return [
        {
            "timestamp": _iso(start + timedelta(seconds=10 * i)),
            "source": host,
            "event_type": event_type,
            "actor": actor,
            "target": target,
            "metadata": metadata,
        }
        for i, (event_type, actor, target, metadata) in enumerate(steps)
    ]


def _noise_rows(
    rng: np.random.Generator, count: int, hosts: list[str], span_seconds: float
) -> list[dict[str, str]]:
    if count == 0:
        return []
    offsets = np.sort(rng.uniform(0, span_seconds, size=count))
    host_idx = rng.integers(0, len(hosts), size=count)
    kinds = rng.integers(0, 4, size=count)
    choice = rng.integers(0, 10_000, size=count)

    rows: list[dict[str, str]] = []
    for i in range(count):
        host = hosts[int(host_idx[i])]
        n = int(choice[i])
        kind = int(kinds[i])
        if kind == 0:
            event_type = "process_execution"
            actor = f"USER{n % 20:02d}"
            target = _NOISE_PROCESSES[n % len(_NOISE_PROCESSES)]
            metadata = _meta(pid=100_000 + i, parentpid=1)
        elif kind == 1:
            event_type = "file_creation"
            actor = f"USER{n % 20:02d}"
            target = f"C:\\Users\\user{n % 20:02d}\\Documents\\file{n}.txt"
            metadata = _meta()
        elif kind == 2:
            event_type = "network_connection"
            actor = _NOISE_PROCESSES[n % len(_NOISE_PROCESSES)]
            target = f"10.{n % 250}.{(n // 250) % 250}.{n % 200 + 1}"
            metadata = _meta(DestinationPort=_NOISE_PORTS[n % len(_NOISE_PORTS)])
        else:
            event_type = "registry_modification"
            actor = f"USER{n % 20:02d}"
            target = f"HKCU\\Software\\Vendor\\App{n % 50}\\Settings\\key{n}"
            metadata = _meta()
        rows.append(
            {
                "timestamp": _iso(_START + timedelta(seconds=float(offsets[i]))),
                "source": host,
                "event_type": event_type,
                "actor": actor,
                "target": target,
                "metadata": metadata,
            }
        )
    return rows


def generate_synthetic_events(
    n_events: int,
    *,
    seed: int = 0,
    hosts: int = 5,
    attack_chains: int = 3,
    span_seconds: float | None = None,
) -> pd.DataFrame:
    """Return a DataFrame with exactly ``n_events`` rows in the log schema,
    sorted by timestamp.

    ``span_seconds`` is the time range the noise is spread over (default: three
    seconds per event, i.e. a busy host). ``attack_chains`` chains of
    ``CHAIN_LENGTH`` events are injected, each on its own host (wrapping round
    when there are more chains than hosts) and evenly spaced through the span.
    """
    if n_events < 0:
        raise ValueError("n_events must be >= 0")
    if hosts < 1:
        raise ValueError("hosts must be >= 1")
    if attack_chains < 0:
        raise ValueError("attack_chains must be >= 0")
    chain_events = attack_chains * CHAIN_LENGTH
    if chain_events > n_events:
        raise ValueError(
            f"{attack_chains} attack chain(s) need {chain_events} events, "
            f"but n_events is only {n_events}"
        )

    span = float(span_seconds) if span_seconds is not None else max(n_events * 3.0, 600.0)
    if span <= 0:
        raise ValueError("span_seconds must be > 0")

    rng = np.random.default_rng(seed)
    host_names = [f"HOST{i + 1:02d}" for i in range(hosts)]

    rows = _noise_rows(rng, n_events - chain_events, host_names, span)
    for k in range(attack_chains):
        start = _START + timedelta(seconds=span * (k + 1) / (attack_chains + 1))
        rows.extend(
            _chain_rows(host_names[k % hosts], start, pid_base=2000 + 10 * k)
        )

    frame = pd.DataFrame(rows, columns=COLUMNS)
    # Stable sort: equal timestamps keep their generation order, so the file is
    # identical for identical inputs.
    frame = frame.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return frame


def write_synthetic_csv(path: str | Path, n_events: int, **kwargs: Any) -> Path:
    """Generate and write the CSV; returns the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    generate_synthetic_events(n_events, **kwargs).to_csv(out, index=False)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic incident log CSV.")
    parser.add_argument("output", help="CSV file to write")
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--chains", type=int, default=3)
    parser.add_argument("--hosts", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    path = write_synthetic_csv(
        args.output,
        args.events,
        seed=args.seed,
        hosts=args.hosts,
        attack_chains=args.chains,
    )
    print(f"Wrote {args.events} events to {path}")


if __name__ == "__main__":
    main()
