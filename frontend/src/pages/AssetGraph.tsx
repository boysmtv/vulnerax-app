import { useEffect, useState } from "react";
import api from "../api";

interface AssetNode {
  id: string;
  type: string;
  vulnerabilities: Array<{ findingId: string; title: string; severity: string }>;
  vulnerabilityCount: number;
  scanIssueCount: number;
  infoCount: number;
}

interface AssetEdge {
  source: string;
  target: string;
  relationship: string;
  label: string;
}

interface AssetGraph {
  nodes: AssetNode[];
  edges: AssetEdge[];
}

export default function AssetGraph() {
  const [graph, setGraph] = useState<AssetGraph | null>(null);
  const [selectedNode, setSelectedNode] = useState<AssetNode | null>(null);

  useEffect(() => {
    api.get("/api/asset-graph").then(r => setGraph(r.data));
  }, []);

  if (!graph) return <div className="p-8">Loading...</div>;

  const serviceNodes = graph.nodes.filter(n => n.type === "SERVICE");
  const endpointNodes = graph.nodes.filter(n => n.type === "ENDPOINT");

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Asset Graph</h1>

      <div className="grid grid-cols-4 gap-6">
        <div className="col-span-3 bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Services</h2>
          <div className="grid grid-cols-3 gap-4">
            {serviceNodes.map(node => (
              <div
                key={node.id}
                className={`p-4 rounded-lg border-2 cursor-pointer transition ${
                  selectedNode?.id === node.id ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:border-gray-300"
                }`}
                onClick={() => setSelectedNode(node)}
              >
                <div className="font-medium truncate">{node.id}</div>
                <div className="flex gap-2 mt-2">
                  {node.vulnerabilityCount > 0 && (
                    <span className="px-2 py-0.5 rounded text-xs bg-red-100 text-red-800">
                      {node.vulnerabilityCount} vuln
                    </span>
                  )}
                  {node.scanIssueCount > 0 && (
                    <span className="px-2 py-0.5 rounded text-xs bg-yellow-100 text-yellow-800">
                      {node.scanIssueCount} issues
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {endpointNodes.length > 0 && (
            <>
              <h2 className="text-lg font-semibold mt-6 mb-4">Endpoints</h2>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {endpointNodes.map(node => (
                  <div key={node.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                    <span className="text-sm font-mono truncate">{node.id}</span>
                    {node.vulnerabilityCount > 0 && (
                      <span className="px-2 py-0.5 rounded text-xs bg-red-100 text-red-800">
                        {node.vulnerabilityCount}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Relationships</h2>
          <div className="space-y-2">
            {graph.edges.map((edge, i) => (
              <div key={i} className="text-sm">
                <div className="font-medium">{edge.relationship}</div>
                <div className="text-gray-500 truncate">{edge.source}</div>
                <div className="text-gray-400">↓</div>
                <div className="text-gray-500 truncate">{edge.target}</div>
                {edge.label && <div className="text-xs text-gray-400">{edge.label}</div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedNode && selectedNode.vulnerabilities.length > 0 && (
        <div className="mt-6 bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Vulnerabilities in {selectedNode.id}</h2>
          <div className="space-y-2">
            {selectedNode.vulnerabilities.map(v => (
              <div key={v.findingId} className="flex items-center gap-3 p-2 bg-gray-50 rounded">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                  v.severity === "CRITICAL" ? "bg-red-100 text-red-800" :
                  v.severity === "HIGH" ? "bg-orange-100 text-orange-800" :
                  "bg-yellow-100 text-yellow-800"
                }`}>
                  {v.severity}
                </span>
                <span className="text-sm">{v.title}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
