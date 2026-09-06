import { useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import dagre, { Graph as DagreGraph, type GraphLabel } from "@dagrejs/dagre";
import "@xyflow/react/dist/style.css";

import type { Incident } from "../types";
import { tacticColor } from "../tactics";

const NODE_WIDTH = 248;
const NODE_HEIGHT = 96;

type ConclusionNodeData = {
  techniqueId: string;
  tactic: string;
  color: string;
  description: string;
  eventCount: number;
};

type ConclusionFlowNode = Node<ConclusionNodeData, "conclusion">;

/** Fixed-size node card; dimensions must match the dagre layout constants. */
function ConclusionNode({ data }: NodeProps<ConclusionFlowNode>) {
  return (
    <div className="chain-node" style={{ ["--tactic" as string]: data.color }}>
      <Handle
        type="target"
        position={Position.Left}
        className="chain-handle"
        isConnectable={false}
      />
      <div className="chain-node-top">
        <span className="chain-node-tech">{data.techniqueId}</span>
        <span className="chain-node-count">
          {data.eventCount} {data.eventCount === 1 ? "EVENT" : "EVENTS"}
        </span>
      </div>
      <p className="chain-node-desc">{data.description}</p>
      <span className="chain-node-tactic">
        <span className="tactic-dot" aria-hidden="true" />
        {data.tactic}
      </span>
      <Handle
        type="source"
        position={Position.Right}
        className="chain-handle"
        isConnectable={false}
      />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  conclusion: ConclusionNode,
};

type BuiltGraph = { nodes: ConclusionFlowNode[]; edges: Edge[] };

function buildGraph(incident: Incident): BuiltGraph {
  const conclusions = incident.conclusions;
  const nodeIds = new Set(conclusions.map((c) => c.conclusion_id));
  const byId = new Map(conclusions.map((c) => [c.conclusion_id, c]));

  // One edge per (parent, child) pair; multiple evidence rows merge and sum.
  const linkTotals = new Map<
    string,
    { source: string; target: string; events: number }
  >();
  for (const conclusion of conclusions) {
    for (const ev of conclusion.evidence) {
      const parent = ev.parent_conclusion_id;
      if (
        !parent ||
        !nodeIds.has(parent) ||
        !nodeIds.has(conclusion.conclusion_id)
      )
        continue;
      const key = `${parent}->${conclusion.conclusion_id}`;
      const entry = linkTotals.get(key) ?? {
        source: parent,
        target: conclusion.conclusion_id,
        events: 0,
      };
      entry.events += ev.event_ids.length;
      linkTotals.set(key, entry);
    }
  }

  const edges: Edge[] = [...linkTotals.values()].map(
    ({ source, target, events }) => {
      // Edge takes the source conclusion's tactic color — same coding as the cards.
      const color = tacticColor(byId.get(source)?.tactic ?? "");
      return {
        id: `${source}->${target}`,
        source,
        target,
        type: "smoothstep",
        animated: true,
        style: { stroke: color, strokeWidth: 1.6 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color,
          width: 16,
          height: 16,
        },
        label: `${events} ${events === 1 ? "EVENT" : "EVENTS"}`,
        labelStyle: {
          fill: "#bdb8c0",
          fontFamily: "Monaco, Menlo, Ubuntu Mono, monospace",
          fontSize: 9,
          fontWeight: 700,
        },
        labelBgStyle: { fill: "#1f1633" },
        labelBgPadding: [6, 3] as [number, number],
        labelBgBorderRadius: 4,
        pathOptions: { borderRadius: 12 },
      };
    },
  );

  const nodes: ConclusionFlowNode[] = conclusions.map((conclusion) => ({
    id: conclusion.conclusion_id,
    type: "conclusion",
    position: { x: 0, y: 0 },
    data: {
      techniqueId: conclusion.technique_id,
      tactic: conclusion.tactic,
      color: tacticColor(conclusion.tactic),
      description: conclusion.description,
      eventCount: conclusion.evidence.reduce(
        (n, ev) => n + ev.event_ids.length,
        0,
      ),
    },
  }));

  // Left-to-right rank layout; dagre centers are converted to top-left coords.
  const layout = new DagreGraph<
    GraphLabel,
    { width: number; height: number; x?: number; y?: number },
    Record<string, unknown>
  >();
  // Tight nodesep keeps disconnected root conclusions from stacking into a
  // needlessly tall column, which would force fitView to zoom way out.
  layout.setGraph({
    rankdir: "LR",
    nodesep: 18,
    ranksep: 72,
    marginx: 16,
    marginy: 16,
  });
  layout.setDefaultEdgeLabel(() => ({}));
  for (const node of nodes) {
    layout.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (const edge of edges) {
    layout.setEdge(edge.source, edge.target);
  }
  dagre.layout(layout);

  return {
    nodes: nodes.map((node) => {
      const placed = layout.node(node.id);
      return {
        ...node,
        position: {
          x: (placed.x ?? 0) - NODE_WIDTH / 2,
          y: (placed.y ?? 0) - NODE_HEIGHT / 2,
        },
      };
    }),
    edges,
  };
}

export default function AttackChain({ incident }: { incident: Incident }) {
  const initial = useMemo(() => buildGraph(incident), [incident]);
  const [nodes, , onNodesChange] = useNodesState<ConclusionFlowNode>(
    initial.nodes,
  );
  const [edges, , onEdgesChange] = useEdgesState<Edge>(initial.edges);

  if (incident.conclusions.length === 0) {
    return (
      <div className="empty-note">
        No conclusions fired — there is no attack chain to draw for this
        dataset.
        <span className="mono">ZERO NODES · GRAPH EMPTY</span>
      </div>
    );
  }

  return (
    <div className="chain-wrap">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        colorMode="dark"
        fitView
        fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
        minZoom={0.25}
        nodesConnectable={false}
        deleteKeyCode={null}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={22}
          size={1.3}
          color="#3f3849"
          bgColor="#150f23"
        />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          bgColor="#150f23"
          maskColor="rgba(21, 15, 35, 0.8)"
          nodeBorderRadius={4}
          nodeColor={(node) => (node.data as ConclusionNodeData).color}
        />
      </ReactFlow>
    </div>
  );
}
