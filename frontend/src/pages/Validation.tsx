import { useEffect, useState } from "react";
import api from "../api";

interface ValidationReport {
  findingId: string;
  readyForPublish: boolean;
  passed: string[];
  failed: string[];
  warnings: string[];
}

export default function Validation() {
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [validation, setValidation] = useState<ValidationReport | null>(null);

  useEffect(() => {
    api.get("/api/findings").then(r => setFindings(r.data.content || []));
  }, []);

  useEffect(() => {
    if (selectedId) {
      api.get(`/api/findings/validation/${selectedId}`).then(r => setValidation(r.data));
    }
  }, [selectedId]);

  const handlePublish = async (findingId: string) => {
    try {
      await api.post(`/api/findings/validation/${findingId}/publish`);
      alert("Finding published successfully!");
      if (selectedId === findingId) {
        api.get(`/api/findings/validation/${findingId}`).then(r => setValidation(r.data));
      }
    } catch (e: any) {
      alert(e.response?.data?.error || "Publish failed");
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Validation Gate</h1>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-1 bg-white rounded-lg shadow p-4">
          <h2 className="font-semibold mb-3">Findings List</h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {findings.map(f => (
              <div
                key={f.id}
                className={`p-2 rounded cursor-pointer text-sm ${
                  selectedId === f.id ? "bg-blue-100" : "hover:bg-gray-50"
                }`}
                onClick={() => setSelectedId(f.id)}
              >
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${
                    f.validated ? "bg-green-500" : "bg-gray-300"
                  }`} />
                  <span className="truncate">{f.title}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="col-span-2 bg-white rounded-lg shadow p-6">
          {validation ? (
            <>
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-lg font-semibold">Validation Report</h2>
                <div className="flex items-center gap-3">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    validation.readyForPublish ? "bg-green-100 text-green-800" : "bg-yellow-100 text-yellow-800"
                  }`}>
                    {validation.readyForPublish ? "Ready to Publish" : "Not Ready"}
                  </span>
                  <button
                    className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                    disabled={!validation.readyForPublish}
                    onClick={() => handlePublish(validation.findingId)}
                  >
                    Publish
                  </button>
                </div>
              </div>

              <div className="space-y-4">
                {validation.passed.length > 0 && (
                  <div>
                    <h3 className="font-medium text-green-700 mb-2">Passed ({validation.passed.length})</h3>
                    {validation.passed.map((p, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm py-1">
                        <span className="text-green-500">✓</span>
                        <span>{p}</span>
                      </div>
                    ))}
                  </div>
                )}

                {validation.failed.length > 0 && (
                  <div>
                    <h3 className="font-medium text-red-700 mb-2">Failed ({validation.failed.length})</h3>
                    {validation.failed.map((f, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm py-1">
                        <span className="text-red-500">✗</span>
                        <span>{f}</span>
                      </div>
                    ))}
                  </div>
                )}

                {validation.warnings.length > 0 && (
                  <div>
                    <h3 className="font-medium text-yellow-700 mb-2">Warnings ({validation.warnings.length})</h3>
                    {validation.warnings.map((w, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm py-1">
                        <span className="text-yellow-500">⚠</span>
                        <span>{w}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-gray-500">
              {selectedId ? "Loading validation..." : "Select a finding to validate"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
