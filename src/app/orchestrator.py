import json
import uuid
from app.parser import parse_log
from app.graph import build_graph
from app.engine import analyze
from app.rules.registry import RULES
from app.models import Incident


def run_analysis(file_path: str) -> Incident:
    result = parse_log(file_path)          # ParseResult object
    graph = build_graph(result.events)     # needs list[Event]
    conclusions = analyze(graph, RULES)    # returns list[Conclusion]
    return Incident(
        id=str(uuid.uuid4()),
        summary=f"Analyzed {len(result.events)} events, found {len(conclusions)} conclusions.",
        conclusions=conclusions,
    )


if __name__ == "__main__":
    import sys
    incident = run_analysis(sys.argv[1])
    print(json.dumps(incident.model_dump(), indent=2, default=str))