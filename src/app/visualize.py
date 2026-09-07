from __future__ import annotations

import matplotlib
import networkx as nx

matplotlib.use("Agg")  # no display needed, just save to file

import matplotlib.pyplot as plt

from app.models import EventType

TYPE_COLORS = {
    EventType.PROCESS_EXECUTION: "#4c72b0",
    EventType.FILE_DOWNLOAD: "#dd8452",
    EventType.FILE_CREATION: "#55a868",
    EventType.REGISTRY_MODIFICATION: "#c44e52",
    EventType.NETWORK_CONNECTION: "#8172b3",
    EventType.POWERSHELL_EXECUTION: "#937860",
    EventType.LOG_DELETION: "#ccb974",
}


def visualize(graph: nx.DiGraph, output_path: str = "graph.png") -> None:
    plt.figure(figsize=(14, 10))
    pos = nx.kamada_kawai_layout(graph)

    node_colors = [
        TYPE_COLORS.get(graph.nodes[n]["event"].event_type, "#999999")
        for n in graph.nodes
    ]
    labels = {
        n: f"{graph.nodes[n]['event'].event_type.value}\n{graph.nodes[n]['event'].target[:20]}"
        for n in graph.nodes
    }

    # nx.draw()'s `arrows` kwarg was removed from its type signature in
    # newer NetworkX releases (arrows are drawn automatically for a
    # DiGraph; there is no longer a boolean toggle on draw() itself).
    # Passing it either silently does nothing or raises depending on
    # version, and Pylance flags it as an invalid parameter against the
    # installed version's stubs. Arrowheads on a DiGraph are drawn by
    # default, so the kwarg is simply unnecessary here -- dropping it
    # keeps the same visual result across NetworkX versions instead of
    # pinning to one specific version's draw() signature.
    nx.draw(
        graph,
        pos,
        node_color=node_colors,
        labels=labels,
        node_size=800,
        font_size=6,
        edge_color="gray",
    )
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    # Bonus (optional): GraphML export so frontend can load raw graph later
    try:
        graphml_path = output_path.rsplit(".", 1)[0] + ".graphml"
        graph_copy = graph.copy()
        for _, data in graph_copy.nodes(data=True):
            data["event"] = data["event"].model_dump_json()
        for _, _, data in graph_copy.edges(data=True):
            if "kind" in data and isinstance(data["kind"], (list, set)):
                data["kind"] = ",".join(str(k) for k in data["kind"])
        nx.write_graphml(graph_copy, graphml_path)
    except Exception as exc:  # noqa: BLE001 - GraphML export is optional/best-effort
        print(f"GraphML export skipped: {exc}")
