"""
Pipeline Orchestrator.

`run_analysis` is the single callable that chains parsing -> graph ->
reasoning -> correlation -> Incident, runnable from the CLI without HTTP.

Fixes KNOWN-ISSUES Phase 2 #1: routes through `dispatch.parse_any_log`, which
picks the correct parser by extension/content, so real Mordor datasets work.

`run_analysis_with_diagnostics` (KNOWN-ISSUES #5) returns the Incident plus
the underlying ParseResult for callers that need parse diagnostics.
`run_analysis` is a thin wrapper kept for backward compatibility.

Phase 3 Step 3 splits the two halves: `analyze_parsed(result)` runs only
graph + engine on an existing ParseResult. `/analyze` parses once, decides
synchronously vs background from the event count, and then either calls
`analyze_parsed` (sync) or schedules it (background) without re-parsing.

Phase 3 Step 4: conclusions are ordered by kill-chain tactic, cross-host
links are found through shared objects, and `summary` is the narrative.
"""

from __future__ import annotations

import json
import sys
import uuid

from app.correlation import build_summary, find_cross_host_links, order_by_kill_chain
from app.dispatch import parse_any_log
from app.engine import analyze
from app.graph import build_graph
from app.models import Incident
from app.parser import ParseResult
from app.rules.registry import RULES
from app.visualize import visualize


def analyze_parsed(result: ParseResult) -> Incident:
    """Run graph building + reasoning on an already-parsed ParseResult.

    Split out so a caller that has to inspect the parse result first (e.g.
    ``POST /analyze`` deciding whether to run synchronously or in the
    background) can parse once and then reuse that work, instead of parsing
    the file twice.
    """
    graph = build_graph(result.events)
    conclusions = order_by_kill_chain(analyze(graph, RULES))
    links = find_cross_host_links(graph, conclusions)
    return Incident(
        id=str(uuid.uuid4()),
        summary=build_summary(len(result.events), result.skipped, conclusions, links),
        conclusions=conclusions,
    )


def run_analysis_with_diagnostics(file_path: str) -> tuple[Incident, ParseResult]:
    """Parse `file_path` (CSV or Mordor NDJSON/JSON, auto-detected),
    build the event graph, run the reasoning engine, and return both the
    resulting Incident and the raw ParseResult (for diagnostics)."""
    result = parse_any_log(file_path)
    return analyze_parsed(result), result


def run_analysis(file_path: str) -> Incident:
    """Backward-compatible entry point returning only the Incident."""
    incident, _result = run_analysis_with_diagnostics(file_path)
    return incident


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
