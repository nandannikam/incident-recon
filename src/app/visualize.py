import matplotlib
matplotlib.use("Agg")  # no display needed, just save to file
import matplotlib.pyplot as plt
import networkx as nx
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

    nx.draw(
        graph, pos,
        node_color=node_colors,
        labels=labels,
        node_size=800,
        font_size=6,
        arrows=True,
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
    except Exception as exc:
        print(f"GraphML export skipped: {exc}") 