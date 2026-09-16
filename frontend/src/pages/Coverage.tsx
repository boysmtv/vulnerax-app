import { useEffect, useState } from "react";
import api from "../api";

interface CoverageReport {
  totalFindings: number;
  confirmedVulnerabilities: number;
  scanIssues: number;
  misconfigurations: number;
  exposures: number;
  informational: number;
  overallCoverage: number;
  findingsBySource: Record<string, number>;
  testedEndpoints: string[];
}

export default function Coverage() {
  const [coverage, setCoverage] = useState<CoverageReport | null>(null);

  useEffect(() => {
    api.get("/api/coverage").then(r => setCoverage(r.data));
  }, []);

  if (!coverage) return <div className="p-8">Loading...</div>;

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Coverage Report</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Findings" value={coverage.totalFindings} color="blue" />
        <StatCard label="Confirmed Vulns" value={coverage.confirmedVulnerabilities} color="red" />
        <StatCard label="Misconfigurations" value={coverage.misconfigurations} color="yellow" />
        <StatCard label="Coverage" value={`${coverage.overallCoverage.toFixed(0)}%`} color="green" />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">By Source</h2>
          <div className="space-y-3">
            {Object.entries(coverage.findingsBySource).map(([source, count]) => (
              <div key={source} className="flex justify-between items-center">
                <span className="text-sm font-medium">{source}</span>
                <div className="flex items-center gap-2">
                  <div className="w-32 bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-blue-600 h-2 rounded-full"
                      style={{ width: `${Math.min(100, (count / coverage.totalFindings) * 100)}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-600 w-8">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Tested Endpoints</h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {coverage.testedEndpoints.map((ep, i) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="truncate">{ep}</span>
              </div>
            ))}
            {coverage.testedEndpoints.length === 0 && (
              <p className="text-gray-500 text-sm">No endpoints tested yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  const colors: Record<string, string> = {
    red: "bg-red-50 text-red-700",
    yellow: "bg-yellow-50 text-yellow-700",
    blue: "bg-blue-50 text-blue-700",
    green: "bg-green-50 text-green-700",
  };
  return (
    <div className={`rounded-lg p-4 ${colors[color] || colors.blue}`}>
      <div className="text-sm font-medium opacity-80">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}
