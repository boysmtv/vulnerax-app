import { useEffect, useState } from "react";
import { api } from "../api/client";

interface RelatedFinding {
  findingId: string;
  title: string;
  findingType: string;
  severity: string;
  reason: string;
}

interface CorrelatedFinding {
  findingId: string;
  title: string;
  findingType: string;
  cwe: string;
  severity: string;
  assetName: string;
  source: string;
  related: RelatedFinding[];
  correlationStrength: string;
  insight: string;
}

export default function Correlation() {
  const [correlations, setCorrelations] = useState<CorrelatedFinding[]>([]);

  useEffect(() => {
    api.get("/api/correlation").then(r => setCorrelations(r.data));
  }, []);

  const highCorrelations = correlations.filter(c => c.correlationStrength === "HIGH");
  const moderateCorrelations = correlations.filter(c => c.correlationStrength === "MODERATE");

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Correlation Engine</h1>

      <div className="grid grid-cols-3 gap-4 mb-8">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Total Findings</div>
          <div className="text-2xl font-bold">{correlations.length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">High Correlation</div>
          <div className="text-2xl font-bold text-red-600">{highCorrelations.length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Moderate Correlation</div>
          <div className="text-2xl font-bold text-yellow-600">{moderateCorrelations.length}</div>
        </div>
      </div>

      <div className="space-y-4">
        {highCorrelations.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold mb-3 text-red-700">High Correlation Findings</h2>
            {highCorrelations.map(c => (
              <FindingCard key={c.findingId} finding={c} />
            ))}
          </div>
        )}

        {moderateCorrelations.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold mb-3 text-yellow-700">Moderate Correlation Findings</h2>
            {moderateCorrelations.map(c => (
              <FindingCard key={c.findingId} finding={c} />
            ))}
          </div>
        )}

        {correlations.length === 0 && (
          <div className="text-center py-8 text-gray-500">No correlations found</div>
        )}
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: CorrelatedFinding }) {
  const [expanded, setExpanded] = useState(false);
  const severityColor: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-800",
    HIGH: "bg-orange-100 text-orange-800",
    MEDIUM: "bg-yellow-100 text-yellow-800",
    LOW: "bg-blue-100 text-blue-800",
    INFO: "bg-gray-100 text-gray-800",
  };

  return (
    <div className="bg-white rounded-lg shadow p-4 mb-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className={`px-2 py-1 rounded text-xs font-medium ${severityColor[finding.severity] || "bg-gray-100"}`}>
            {finding.severity}
          </span>
          <span className="font-medium">{finding.title}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">{finding.source}</span>
          <span className={`px-2 py-1 rounded text-xs font-medium ${
            finding.correlationStrength === "HIGH" ? "bg-red-100 text-red-800" : "bg-yellow-100 text-yellow-800"
          }`}>
            {finding.correlationStrength}
          </span>
        </div>
      </div>
      <p className="text-sm text-gray-600 mt-2">{finding.insight}</p>
      {expanded && finding.related.length > 0 && (
        <div className="mt-3 pt-3 border-t">
          <div className="text-xs font-medium text-gray-500 mb-2">Related Findings ({finding.related.length})</div>
          {finding.related.map(r => (
            <div key={r.findingId} className="flex items-center gap-2 text-sm py-1">
              <span className={`px-1.5 py-0.5 rounded text-xs ${severityColor[r.severity] || "bg-gray-100"}`}>
                {r.severity}
              </span>
              <span>{r.title}</span>
              <span className="text-gray-400">- {r.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
