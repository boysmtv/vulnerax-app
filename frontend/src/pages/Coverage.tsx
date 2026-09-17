import { useEffect, useState } from "react";
import { api } from "../api/client";

interface CoverageItem {
  id: string;
  domain: string;
  status: string;
  coveragePercent: number;
  provider: string;
  projectId?: string;
}

interface Project {
  id: string;
  name: string;
}

export default function Coverage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [coverageData, setCoverageData] = useState<CoverageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [projectsLoaded, setProjectsLoaded] = useState(false);

  useEffect(() => {
    api.get("/api/v1/projects").then((r) => {
      const list = r.data.data?.content ?? r.data.data ?? [];
      setProjects(list);
      if (list.length > 0) setSelectedProject(list[0].id);
      setProjectsLoaded(true);
    }).catch(() => setProjectsLoaded(true));
  }, []);

  useEffect(() => {
    if (!selectedProject) return;
    setLoading(true);
    api
      .get(`/api/v1/coverage?projectId=${selectedProject}`)
      .then((r) => {
        const data = r.data.data;
        if (Array.isArray(data)) setCoverageData(data);
        else if (data?.content) setCoverageData(data.content);
        else setCoverageData([]);
      })
      .catch(() => setCoverageData([]))
      .finally(() => setLoading(false));
  }, [selectedProject]);

  const handleCreateDemo = async () => {
    try {
      await api.post("/api/v1/coverage", { projectId: selectedProject, demo: true });
      const r = await api.get(`/api/v1/coverage?projectId=${selectedProject}`);
      const data = r.data.data;
      if (Array.isArray(data)) setCoverageData(data);
      else if (data?.content) setCoverageData(data.content);
      else setCoverageData([]);
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.message || "Failed to create";
      window.alert(msg);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Security Coverage</h1>
        <p className="text-sm text-slate-500">SAST • SCA • Secrets • DAST coverage analysis across your assets</p>
      </div>

      <div className="flex items-center gap-4">
        <select
          value={selectedProject}
          onChange={(e) => setSelectedProject(e.target.value)}
          className="border rounded-lg px-3 py-2 text-sm"
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
        <button onClick={handleCreateDemo} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm">
          Create Demo
        </button>
      </div>

      {loading ? (
        <div className="text-sm text-slate-500">Loading...</div>
      ) : coverageData.length === 0 ? (
        <div className="text-sm text-slate-400">No data yet — Security Coverage will appear after your first scan</div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {coverageData.map((item) => (
              <div key={item.id} className="bg-white rounded-xl border p-4">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-semibold">{item.domain}</span>
                  <span className={`text-xs px-2 py-1 rounded-full ${item.status === "TESTED" ? "bg-green-100 text-green-700" : "bg-slate-100 text-slate-600"}`}>
                    {item.status}
                  </span>
                </div>
                <div className="text-2xl font-bold">{item.coveragePercent}%</div>
                <div className="text-xs text-slate-500 mt-1">Provider: {item.provider}</div>
                <div className="mt-2 h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div className="h-full bg-indigo-600 rounded-full" style={{ width: `${item.coveragePercent}%` }} />
                </div>
              </div>
            ))}
          </div>
          <pre className="bg-slate-50 rounded-lg p-4 text-xs overflow-auto max-h-64">{JSON.stringify(coverageData, null, 2)}</pre>
        </>
      )}

      <div className="text-xs text-slate-400">API: GET /api/v1/coverage</div>
    </div>
  );
}
