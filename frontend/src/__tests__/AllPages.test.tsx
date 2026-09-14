import { vi, describe, it, expect } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

const mockLogin = vi.fn()
const mockLogout = vi.fn()

vi.mock('../api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
  },
}))
vi.mock('../store/auth', () => ({
  useAuth: vi.fn(() => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER', fullName: 'Test User' }, login: mockLogin, logout: mockLogout })),
}))

import { api } from '../api/client'
import { useAuth } from '../store/auth'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })
const wrap = (c: QueryClient) => ({ children }: any) => <QueryClientProvider client={c}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>

// ─── Login ───
import Login from '../pages/Login'
describe('Login', () => {
  it('renders inputs', () => { render(<Login />, { wrapper: wrap(qc()) }); expect(screen.getByPlaceholderText(/email/i)).toBeInTheDocument(); expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument() })
  it('shows Welcome back', () => { render(<Login />, { wrapper: wrap(qc()) }); expect(screen.getByText('Welcome back')).toBeInTheDocument() })
  it('toggles to register', () => { render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByText('Register')); expect(screen.getByRole('heading', { name: 'Create account' })).toBeInTheDocument(); expect(screen.getByPlaceholderText(/full name/i)).toBeInTheDocument() })
  it('toggles back to login', () => { render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByText('Register')); fireEvent.click(screen.getByText('Login')); expect(screen.getByText('Welcome back')).toBeInTheDocument(); expect(screen.queryByPlaceholderText(/full name/i)).not.toBeInTheDocument() })
  it('submits login', async () => { vi.mocked(api.post).mockResolvedValue({ data: { success: true, data: { accessToken: 'tok', user: {} } } }); render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByRole('button', { name: /sign in/i })); await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/auth/login', expect.objectContaining({ email: 'admin@vulnerax.io' }))) })
  it('shows error', async () => { vi.mocked(api.post).mockRejectedValue({ response: { data: { message: 'Bad creds' } } }); render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByRole('button', { name: /sign in/i })); await waitFor(() => expect(screen.getByText('Bad creds')).toBeInTheDocument()) })
  it('shows loading', () => { vi.mocked(api.post).mockReturnValueOnce(new Promise(() => {})); render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByRole('button', { name: /sign in/i })); expect(screen.getByText('Please wait...')).toBeInTheDocument() })
  it('submits register', async () => { vi.mocked(api.post).mockResolvedValue({ data: { success: true, data: { token: 't', user: {} } } }); render(<Login />, { wrapper: wrap(qc()) }); fireEvent.click(screen.getByText('Register')); fireEvent.change(screen.getByPlaceholderText(/full name/i), { target: { value: 'New User' } }); fireEvent.click(screen.getByRole('button', { name: /create account/i })); await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/auth/register', expect.objectContaining({ fullName: 'New User' }))) })
  it('shows branding', () => { render(<Login />, { wrapper: wrap(qc()) }); expect(screen.getByText('VulneraX')).toBeInTheDocument() })
})

// ─── Dashboard ───
import Dashboard from '../pages/Dashboard'
describe('Dashboard', () => {
  const setup = (d: any) => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: d } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>) }
  it('renders title', () => { setup({ securityScore: 75, critical: 5, high: 20, totalAssets: 42, kev: 2, internetExposed: 3, slaBreached: 1, bySeverity: { CRITICAL: 5, HIGH: 20, MEDIUM: 30, LOW: 40 } }); expect(screen.getByText('Security Command Center')).toBeInTheDocument() })
  it('shows score', async () => { setup({ securityScore: 75, critical: 0, high: 0, totalAssets: 0, kev: 0, internetExposed: 0, slaBreached: 0, bySeverity: {} }); await waitFor(() => expect(screen.getByText('75')).toBeInTheDocument()) })
  it('shows empty state', async () => { setup({ securityScore: 0, critical: 0, high: 0, totalAssets: 0, kev: 0, internetExposed: 0, slaBreached: 0 }); await waitFor(() => expect(screen.getByText(/No findings yet/)).toBeInTheDocument()) })
  it('links', async () => { setup({ securityScore: 0, critical: 0, high: 0, totalAssets: 0, kev: 0, internetExposed: 0, slaBreached: 0, bySeverity: {} }); await waitFor(() => { expect(screen.getByText('Generate Report').closest('a')).toHaveAttribute('href', '/reports') }) })
})

// ─── Findings ───
import Findings from '../pages/Findings'
describe('Findings', () => {
  const setup = (data: any[] = [{ id: '1', findingId: 'FND-001', title: 'SQL Injection', severity: 'CRITICAL', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03', source: 'SAST', status: 'OPEN', owner: 'dev1', riskScore: 92, riskLevel: 'CRITICAL', assetName: 'API', environment: 'PROD', kev: true, internetExposed: true }]) => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: data, totalElements: data.length } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Findings /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Vulnerability Explorer')).toBeInTheDocument() })
  it('shows data', async () => { setup(); await waitFor(() => expect(screen.getByText(/FND-001/)).toBeInTheDocument()) })
  it('filters', async () => { setup(); await waitFor(() => expect(screen.getByText(/FND-001/)).toBeInTheDocument()); fireEvent.change(screen.getByDisplayValue('All severity'), { target: { value: 'HIGH' } }); await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/v1/findings', expect.objectContaining({ params: expect.objectContaining({ severity: 'HIGH' }) }))) })
  it('resolves', async () => { setup(); await waitFor(() => expect(screen.getByText(/FND-001/)).toBeInTheDocument()); fireEvent.click(screen.getAllByText('Resolve')[0]); await waitFor(() => expect(api.put).toHaveBeenCalled()) })
  it('empty', async () => { setup([]); await waitFor(() => expect(screen.getByText(/No findings/)).toBeInTheDocument()) })
})

// ─── FindingDetail ───
import FindingDetail from '../pages/FindingDetail'
describe('FindingDetail', () => {
  const detail = { id: '1', findingId: 'FND-001', title: 'SQLi', cwe: 'CWE-89', owasp: 'A03', source: 'SAST', severity: 'CRITICAL', cvss: 9.8, epss: 0.95, kev: true, confidence: 'HIGH', status: 'OPEN', riskScore: 92, riskLevel: 'CRITICAL', internetExposed: true, reachable: true, description: 'SQL injection', assetName: 'API', environment: 'PROD', owner: 'dev1', filePath: 'Login.java', lineNumber: 42, functionName: 'login', dataFlow: 'HTTP', businessCriticality: 'CRITICAL', recommendation: 'Fix it', codeSnippet: 'sql', fingerprint: 'abc', slaStatus: 'OK', slaDueAt: '2026-01-15' }
  const ai = { rootCause: 'Concat', impact: 'DB', remediation: 'Fix', codeFix: 'ps', priority: 'P0', summary: 'SQLi', testRecommendation: 'test' }
  const setup = (overrides: any = {}) => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/evidence')) return Promise.resolve({ data: { success: true, data: [{ id: 'e1', type: 'STACK', sha256: 'abc123', content: 'Ex', createdAt: '2026-01-10', author: 's' }] } }); if (url.includes('/correlation')) return Promise.resolve({ data: { success: true, data: { attackPathCandidate: 'path', correlated: [{ id: 'c1', title: 'Rel', severity: 'HIGH', type: 'DAST', assetName: 'A' }] } } }); if (url.includes('/ai/explain')) return Promise.resolve({ data: { success: true, data: ai } }); if (url.includes('/findings/1')) return Promise.resolve({ data: { success: true, data: { ...detail, ...overrides } } }); return Promise.resolve({ data: { success: true, data: null } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter initialEntries={['/findings/1']}><Routes><Route path="/findings/:id" element={<FindingDetail />} /></Routes></MemoryRouter></QueryClientProvider>) }
  it('loading', () => { vi.mocked(api.get).mockReturnValue(new Promise(() => {})); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter initialEntries={['/findings/1']}><Routes><Route path="/findings/:id" element={<FindingDetail />} /></Routes></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Loading...')).toBeInTheDocument() })
  it('renders', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()) })
  it('shows risk', async () => { setup(); await waitFor(() => expect(screen.getByText('92')).toBeInTheDocument()) })
  it('shows tabs', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); expect(screen.getByRole('button', { name: /overview/i })).toBeInTheDocument(); expect(screen.getByRole('button', { name: /code/i })).toBeInTheDocument(); expect(screen.getByRole('button', { name: /ai/i })).toBeInTheDocument() })
  it('overview', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); expect(screen.getByText(/What happened/)).toBeInTheDocument() })
  it('code tab', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); fireEvent.click(screen.getByRole('button', { name: /code/i })); expect(screen.getByText(/Code Path/)).toBeInTheDocument() })
  it('evidence tab', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); fireEvent.click(screen.getByRole('button', { name: /evidence/i })); expect(screen.getByText(/STACK/)).toBeInTheDocument() })
  it('correlation tab', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); fireEvent.click(screen.getByRole('button', { name: /correlation/i })); expect(screen.getByText('Rel')).toBeInTheDocument() })
  it('ai tab', async () => { setup(); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); fireEvent.click(screen.getByRole('button', { name: /ai/i })); expect(screen.getByText('AI Fix Assistant')).toBeInTheDocument() })
  it('hides badges', async () => { setup({ internetExposed: false, reachable: false }); await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument()); expect(screen.queryByText('Internet Exposed')).not.toBeInTheDocument() })
})

// ─── Assets ───
import Assets from '../pages/Assets'
describe('Assets', () => {
  const setup = () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 42, internetExposed: 3, discoveryDelta: { newLast24h: 5 }, byType: {} } } }); if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'API', identifier: 'id', technology: 'Java', type: 'API', environment: 'PROD', criticality: 'CRITICAL', internetExposed: true, owner: 't' }], totalElements: 1 } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T', organizationId: 'o' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Assets /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Asset Inventory')).toBeInTheDocument() })
  it('shows data', async () => { setup(); await waitFor(() => expect(screen.getByText('API')).toBeInTheDocument()) })
  it('toggle form', () => { setup(); fireEvent.click(screen.getByText('New Asset')); expect(screen.getByText('Register Asset')).toBeInTheDocument(); fireEvent.click(screen.getByText('New Asset')); expect(screen.queryByText('Register Asset')).not.toBeInTheDocument() })
  it('empty', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 0, internetExposed: 0, discoveryDelta: { newLast24h: 0 }, byType: {} } } }); if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [], totalElements: 0 } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T', organizationId: 'o' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Assets /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText(/No assets/)).toBeInTheDocument()) })
})

// ─── Scans ───
import Scans from '../pages/Scans'
describe('Scans', () => {
  const setup = (scans: any[] = [{ id: 's1', scannerType: 'SAST', target: 'repo', profile: 'STANDARD', status: 'COMPLETED', findingsCount: 5, durationMs: 30000, initiatedBy: 'd', createdAt: '2026-01-10' }]) => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: scans, totalElements: scans.length } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Scans /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Scan Center')).toBeInTheDocument() })
  it('empty', async () => { setup([]); await waitFor(() => expect(screen.getByText(/No scans yet/)).toBeInTheDocument()) })
  it('orchestrator', () => { setup(); expect(screen.getByText('Scan Orchestrator')).toBeInTheDocument() })
  it('selects type', () => { setup(); fireEvent.change(screen.getByDisplayValue('SAST'), { target: { value: 'DAST' } }); expect(screen.getByDisplayValue('DAST')).toBeInTheDocument() })
})

// ─── Projects ───
import Projects from '../pages/Projects'
describe('Projects', () => {
  const setup = () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/organizations')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'o1', name: 'Acme', slug: 'ac', tier: 'E' }] } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Proj', description: 'Desc', criticality: 'HIGH', status: 'ACTIVE' }] } } }); if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'w1' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Projects /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Organization & Project Hierarchy')).toBeInTheDocument() })
  it('shows org', async () => { setup(); await waitFor(() => expect(screen.getByText('Acme')).toBeInTheDocument()) })
  it('example', () => { setup(); expect(screen.getByText(/Example Final Assessment/)).toBeInTheDocument() })
})

// ─── Reports ───
import Reports from '../pages/Reports'
describe('Reports', () => {
  const setup = (reports: any[] = [{ id: 'r1', title: 'Exec', type: 'EXEC', format: 'PDF', classification: 'C', status: 'READY', createdAt: '2026-01-10' }]) => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); if (url.includes('/reports')) return Promise.resolve({ data: { success: true, data: reports } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Reports /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Reporting Engine')).toBeInTheDocument() })
  it('generate', async () => { setup(); fireEvent.click(screen.getByText('Generate')); await waitFor(() => expect(api.post).toHaveBeenCalled()) })
  it('empty', async () => { setup([]); await waitFor(() => expect(screen.getByText(/No reports/)).toBeInTheDocument()) })
  it('sample', () => { setup(); expect(screen.getByText('Executive Report (sample structure)')).toBeInTheDocument() })
})

// ─── Graph ───
import Graph from '../pages/Graph'
describe('Graph', () => {
  const setup = () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [{ id: 'a1', entryPoint: 'Inet', weakness: 'BOLA', asset: 'API', risk: 94, riskLevel: 'CRIT', chain: ['A'], impact: 'Breach', mitigation: 'Fix' }] } }); if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [{ id: 'n1', label: 'N1', type: 'ASSET' }], edges: [{ from: 'a', to: 'b', label: 'E' }], stats: {} } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Graph /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Security Graph & Attack Path')).toBeInTheDocument() })
  it('attack path', async () => { setup(); await waitFor(() => expect(screen.getByText('BOLA')).toBeInTheDocument()) })
  it('empty', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } }); if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: [], stats: {} } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Graph /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText(/No attack paths yet/)).toBeInTheDocument()) })
})

// ─── Mobile ───
import Mobile from '../pages/Mobile'
describe('Mobile', () => {
  const setup = () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/mobile') && url.includes('/workspace')) return Promise.resolve({ data: { success: true, data: { overview: {}, manifest: 'm', endpoints: ['e'], masvs: [{ control: 'C', status: 'PASS', severity: 'L' }], callGraph: ['a→b'] } } }); if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [{ id: 'm1', fileName: 'app.apk', platform: 'ANDROID', masvsScore: 72, status: 'DONE', fileSha256: 'abc', fileSize: 10000000 }] } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><Mobile /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText('Mobile Security & Reverse Engineering')).toBeInTheDocument() })
  it('empty', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Mobile /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText(/No artifacts/)).toBeInTheDocument()) })
  it('upload', async () => { setup(); fireEvent.click(screen.getByText('Analyze')); await waitFor(() => expect(api.post).toHaveBeenCalled()) })
})

// ─── Coverage ───
import Coverage from '../pages/Coverage'
describe('Coverage', () => {
  it('renders', () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', name: 'SAST' }] } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Coverage /></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Security Coverage')).toBeInTheDocument() })
  it('loading', () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return new Promise(() => {}); }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Coverage /></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Security Coverage')).toBeInTheDocument() })
  it('empty', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Coverage /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText(/No data/)).toBeInTheDocument()) })
  it('create', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Coverage /></MemoryRouter></QueryClientProvider>); fireEvent.click(screen.getByText('Create Demo')); await waitFor(() => expect(api.post).toHaveBeenCalled()) })
})

// ─── Layout ───
import Layout from '../components/Layout'
describe('Layout', () => {
  it('children', () => { vi.mocked(useAuth).mockReturnValue({ token: 't', user: { email: 'e', role: 'r', fullName: 'n' } as any, login: vi.fn(), logout: vi.fn() }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Layout><div>Child</div></Layout></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Child')).toBeInTheDocument() })
  it('branding', () => { vi.mocked(useAuth).mockReturnValue({ token: 't', user: { email: 'e', role: 'r', fullName: 'n' } as any, login: vi.fn(), logout: vi.fn() }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Layout><div>C</div></Layout></MemoryRouter></QueryClientProvider>); expect(screen.getByText('VulneraX')).toBeInTheDocument() })
  it('primary nav', () => { vi.mocked(useAuth).mockReturnValue({ token: 't', user: { email: 'e', role: 'r', fullName: 'n' } as any, login: vi.fn(), logout: vi.fn() }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Layout><div>C</div></Layout></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Dashboard')).toBeInTheDocument(); expect(screen.getByText('Findings')).toBeInTheDocument() })
  it('advanced toggle', () => { vi.mocked(useAuth).mockReturnValue({ token: 't', user: { email: 'e', role: 'r', fullName: 'n' } as any, login: vi.fn(), logout: vi.fn() }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Layout><div>C</div></Layout></MemoryRouter></QueryClientProvider>); fireEvent.click(screen.getByRole('button', { name: /Advanced/ })); expect(screen.getByText('Projects')).toBeInTheDocument() })
  it('logout', () => { const ml = vi.fn(); vi.mocked(useAuth).mockReturnValue({ token: 't', user: { email: 'e', role: 'r', fullName: 'n' } as any, login: vi.fn(), logout: ml }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Layout><div>C</div></Layout></MemoryRouter></QueryClientProvider>); fireEvent.click(screen.getByText('Logout')); expect(ml).toHaveBeenCalled() })
})

// ─── Notifications ───
import Notifications from '../pages/Notifications'
describe('Notifications', () => {
  it('renders', () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'n1', title: 'Alert', type: 'T', severity: 'S', read: false, createdAt: '2026' }], totalElements: 1 } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Notifications /></MemoryRouter></QueryClientProvider>); expect(screen.getByText('Notifications')).toBeInTheDocument() })
  it('empty', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [], totalElements: 0 } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Notifications /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText('No data yet')).toBeInTheDocument()) })
  it('data', async () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'n1', title: 'Alert', type: 'T', severity: 'S', read: false, createdAt: '2026' }], totalElements: 1 } } }); if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'T' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); const c = qc(); render(<QueryClientProvider client={c}><MemoryRouter><Notifications /></MemoryRouter></QueryClientProvider>); await waitFor(() => expect(screen.getByText('Alert')).toBeInTheDocument()) })
})

// ─── OneClickTest ───
import OneClickTest from '../pages/OneClickTest'
describe('OneClickTest', () => {
  const setup = () => { vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } }); if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', organizationId: 'org1' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); vi.mocked(api.post).mockImplementation((url: any) => { if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'r1' } } }); return Promise.resolve({ data: { success: true, data: { id: '1' } } }) }); const c = qc(); return render(<QueryClientProvider client={c}><MemoryRouter><OneClickTest /></MemoryRouter></QueryClientProvider>) }
  it('renders', () => { setup(); expect(screen.getByText(/Test Platform/)).toBeInTheDocument() })
  it('step 1', () => { setup(); expect(screen.getByText(/Langkah 1/)).toBeInTheDocument() })
  it('step 2', async () => { setup(); await waitFor(() => expect(screen.getByText(/Test Project/)).toBeInTheDocument()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } }); fireEvent.click(screen.getByText(/Lanjut/)); expect(screen.getByText(/Langkah 2/)).toBeInTheDocument() })
  it('platforms', async () => { setup(); await waitFor(() => expect(screen.getByText(/Test Project/)).toBeInTheDocument()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } }); fireEvent.click(screen.getByText(/Lanjut/)); expect(screen.getByText('WEB')).toBeInTheDocument(); expect(screen.getByText('API')).toBeInTheDocument() })
  it('back', async () => { setup(); await waitFor(() => expect(screen.getByText(/Test Project/)).toBeInTheDocument()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } }); fireEvent.click(screen.getByText(/Lanjut/)); fireEvent.click(screen.getByText(/Kembali/)); expect(screen.getByText(/Langkah 1/)).toBeInTheDocument() })
  it('start', async () => { vi.useFakeTimers({ shouldAdvanceTime: true }); setup(); await waitFor(() => expect(screen.getByText(/Test Project/)).toBeInTheDocument()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } }); fireEvent.click(screen.getByText(/Lanjut/)); fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://ex.com' } }); vi.mocked(api.get).mockImplementation((url: any) => { if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } }); if (url.includes('/one-click')) return Promise.resolve({ data: { data: { status: 'COMPLETED', findingsCount: 1, target: 'https://ex.com', detectedType: 'WEB', progress: 100 } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }); vi.mocked(api.post).mockResolvedValue({ data: { data: { id: 'r1' } } }); fireEvent.click(screen.getByText(/Test Sekarang/)); await waitFor(() => expect(screen.getByText(/Progress Live/)).toBeInTheDocument()); vi.useRealTimers() })
  it('empty alert', async () => { vi.spyOn(window, 'alert').mockImplementation(() => {}); setup(); await waitFor(() => expect(screen.getByText(/Test Project/)).toBeInTheDocument()); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } }); fireEvent.click(screen.getByText(/Lanjut/)); fireEvent.click(screen.getByText(/Test Sekarang/)); await waitFor(() => expect(window.alert).toHaveBeenCalled()); vi.mocked(window.alert).mockRestore() })
})
