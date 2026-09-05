import json
import uuid
from app.parser import parse_log
from app.graph import build_graph
from app.engine import analyze
from app.rules.registry import RULES
from app.models import Incident
from app.visualize import visualize


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

    file_path = sys.argv[1]
    incident = run_analysis(file_path)
    print(json.dumps(incident.model_dump(), indent=2, default=str))

    if "--viz" in sys.argv:
        result = parse_log(file_path)
        graph = build_graph(result.events)
        visualize(graph, output_path="graph.png")
        print("Saved graph.png")