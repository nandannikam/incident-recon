"""
Pipeline Orchestrator.

`run_analysis` is the single callable that chains parsing -> graph ->
reasoning -> Incident, runnable from the CLI without HTTP.

Fixes KNOWN-ISSUES Phase 2 #1: previously hardcoded `parse_log` (CSV-only),
so any real Mordor dataset (`.json`/`.ndjson`) crashed with a pandas
`ParserError` here (and propagated as a 500 from `POST /analyze`). Now
routes through `dispatch.parse_any_log`, which picks the correct parser by
extension/content and normalizes pid metadata so graph building behaves
the same regardless of source format.
"""

from __future__ import annotations

import json
import sys
import uuid

from app.dispatch import parse_any_log
from app.engine import analyze
from app.graph import build_graph
from app.models import Incident
from app.rules.registry import RULES
from app.visualize import visualize


def run_analysis(file_path: str) -> Incident:
    """Parse `file_path` (CSV or Mordor NDJSON/JSON, auto-detected),
    build the event graph, run the reasoning engine, and assemble the
    resulting Incident."""
    result = parse_any_log(file_path)
    graph = build_graph(result.events)
    conclusions = analyze(graph, RULES)
    return Incident(
        id=str(uuid.uuid4()),
        summary=(
            f"Analyzed {len(result.events)} events "
            f"(skipped {result.skipped} malformed rows), "
            f"found {len(conclusions)} conclusions."
        ),
        conclusions=conclusions,
    )


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python -m app.orchestrator <file_path> [--viz]", file=sys.stderr)
        raise SystemExit(2)

    file_path = sys.argv[1]
    incident = run_analysis(file_path)
    print(json.dumps(incident.model_dump(), indent=2, default=str))

    if "--viz" in sys.argv:
        result = parse_any_log(file_path)
        graph = build_graph(result.events)
        visualize(graph, output_path="graph.png")
        print("Saved graph.png")


if __name__ == "__main__":
    main()
