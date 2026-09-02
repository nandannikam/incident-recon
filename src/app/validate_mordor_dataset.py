"""
Phase 2, Step 2 — Real Dataset Integration: validation & coverage report.

Run this after downloading Mordor atomic datasets into src/data/mordor/.
It parses every .ndjson / .json file in that folder with parse_mordor(),
and prints a Pandas-based coverage report showing:
  - how many events of each EventType were found per file
  - parse success/skip counts per file
  - whether all 7 EventTypes are covered across the whole folder

This is the "prove the pipeline runs on real data" checkpoint from the
roadmap's Step 2 Done-When criterion.

Usage:
    python -m app.validate_mordor_dataset src/data/mordor
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

from app.models import EventType
from app.mordor_parser import parse_mordor


def build_coverage_report(mordor_dir: str | Path) -> pd.DataFrame:
    """
    Parse every NDJSON/JSON file in mordor_dir and return a per-file,
    per-EventType count matrix as a DataFrame (rows = files, columns =
    EventType values + 'skipped' + 'total_rows').
    """
    directory = Path(mordor_dir)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    dataset_files = sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in {".ndjson", ".json", ".jsonl"}
    )

    if not dataset_files:
        raise FileNotFoundError(
            f"No .ndjson/.json/.jsonl files found in {directory}. "
            "Download Mordor atomic datasets there first."
        )

    rows: list[dict[str, object]] = []
    for path in dataset_files:
        result = parse_mordor(path)
        counts = {et.value: 0 for et in EventType}
        for event in result.events:
            counts[event.event_type.value] += 1

        row: dict[str, object] = {"file": path.name, "total_rows": result.total_rows,
                                   "parsed": len(result.events), "skipped": result.skipped}
        row.update(counts)
        rows.append(row)

    df = pd.DataFrame(rows).set_index("file")
    return df


def print_report(df: pd.DataFrame) -> None:
    print("\n=== Mordor Dataset Coverage Report ===\n")
    print(df.to_string())

    event_type_cols = [et.value for et in EventType]
    totals = df[event_type_cols].sum()
    covered = totals[totals > 0].index.tolist()
    missing = totals[totals == 0].index.tolist()

    print("\n--- Coverage across all files ---")
    print(f"Covered event types ({len(covered)}/7): {covered}")
    if missing:
        print(f"MISSING event types: {missing}")
    else:
        print("All 7 event types are covered. ✅")

    total_skipped = int(df["skipped"].sum())
    total_rows = int(df["total_rows"].sum())
    pct = 100 * (1 - total_skipped / total_rows) if total_rows else 0.0
    print(f"\nRelevant-event extraction rate: {total_rows - total_skipped}/{total_rows} "
          f"rows ({pct:.1f}%) across {len(df)} files.")
    print(
        "Note: a low percentage here is EXPECTED and not a bug. Raw Windows/Sysmon "
        "captures contain many EventIDs (process-exit, handle-access, WFP filtering, "
        "Sysmon config-change, etc.) that fall outside our 7-type taxonomy on purpose. "
        "Run print_skip_reasons() / see the diagnostic below to confirm skips are all "
        "'unmapped EventID' and not a real parsing failure."
    )


def print_skip_reasons(mordor_dir: str | Path, sample_per_file: int = 5) -> None:
    """
    Diagnostic helper: re-parses each file and prints a small sample of the
    actual skip reasons (not just counts), grouped by the exception type, so
    you can see WHY rows are being skipped instead of just how many.
    """
    directory = Path(mordor_dir)
    dataset_files = sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in {".ndjson", ".json", ".jsonl"}
    )

    print("\n=== Skip Reason Diagnostic ===")
    for path in dataset_files:
        result = parse_mordor(path)
        if result.skipped == 0:
            continue

        print(f"\n--- {path.name} ({result.skipped} skipped) ---")

        # Group errors by their exception type / message shape for a quick read.
        reason_counts: dict[str, int] = {}
        for err in result.errors:
            # err looks like "line 12: MordorParseError: unmapped EventID: 4663"
            key = err.split(":", 2)[1].strip() if err.count(":") >= 2 else err
            reason_counts[key] = reason_counts.get(key, 0) + 1

        for reason, count in sorted(reason_counts.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>6}x  {reason}")

        print("  Sample raw errors:")
        for err in result.errors[:sample_per_file]:
            print(f"    {err}")


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "src/data/mordor"
    report_df = build_coverage_report(target_dir)
    print_report(report_df)
    print_skip_reasons(target_dir)