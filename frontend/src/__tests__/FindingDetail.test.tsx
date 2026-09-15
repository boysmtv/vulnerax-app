import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

const { mockGet } = vi.hoisted(() => ({
  mockGet: vi.fn(),
}))
const defaultMockImpl = (url: string) => {
  if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'String concatenation', impact: 'Data breach', remediation: 'Use prepared statements', codeFix: 'const query = "SELECT * FROM users WHERE id=$1"', priority: 'P0', summary: 'SQL injection found', testRecommendation: 'Add integration test' } } })
  if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [{ id: 'e1', type: 'HTTP_REQUEST', sha256: 'abc123def456789', content: 'GET /login HTTP/1.1', createdAt: '2025-11-15T10:00:00Z', author: 'scanner' }] } })
  if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { attackPathCandidate: 'Yes', correlated: [{ id: 'c1', title: 'Related XSS', severity: 'HIGH', type: 'SAST', assetName: 'Payment API' }] } } })
  if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'SQL Injection', cwe: 'CWE-89', owasp: 'A03', source: 'SEMGREP', riskScore: 92, riskLevel: 'CRITICAL', cvss: 9.8, epss: 0.95, kev: true, severity: 'CRITICAL', confidence: 'HIGH', status: 'OPEN', internetExposed: true, reachable: true, description: 'SQL injection in login form', assetName: 'Payment API', environment: 'PRODUCTION', owner: 'Team Alpha', filePath: 'src/auth/login.ts', lineNumber: 42, functionName: 'authenticate', dataFlow: 'HTTP → Controller → Service → DB', businessCriticality: 'CRITICAL', recommendation: 'Use parameterized queries', codeSnippet: 'const query = "SELECT * FROM users WHERE id=" + userId', fingerprint: 'abc123def456', slaStatus: 'BREACHED', slaDueAt: '2025-12-01T00:00:00Z' } } })
  return Promise.resolve({ data: { success: true, data: { content: [], totalElements: 0, totalPages: 0 } } })
}
mockGet.mockImplementation(defaultMockImpl)
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import FindingDetail from '../pages/FindingDetail'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrapWithRoute = (initialEntries: string[] = ['/findings/1']) => (
  <QueryClientProvider client={qc()}>
    <MemoryRouter initialEntries={initialEntries}>
      <Routes><Route path="/findings/:id" element={<FindingDetail />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>
)

describe('FindingDetail', () => {
  beforeEach(() => { vi.clearAllMocks(); mockGet.mockImplementation(defaultMockImpl) })

  it('shows loading state initially', () => {
    mockGet.mockReturnValueOnce(new Promise(() => {}))
    render(wrapWithRoute())
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('renders finding title after data loads', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
  })

  it('renders finding metadata', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText(/FND-001.*CWE-89.*A03.*SEMGREP/)).toBeInTheDocument())
  })

  it('displays risk score and risk level', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('92').closest('div')).toHaveTextContent('92'))
  })

  it('displays CVSS and EPSS values', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText(/CVSS 9.8.*EPSS/)).toBeInTheDocument())
  })

  it('displays KEV badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('KEV')).toBeInTheDocument())
  })

  it('displays severity badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('CRITICAL', { selector: '.rounded' })).toBeInTheDocument())
  })

  it('displays confidence badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText(/confidence/)).toBeInTheDocument())
  })

  it('displays status badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('OPEN')).toBeInTheDocument())
  })

  it('displays Internet Exposed badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('Internet Exposed')).toBeInTheDocument())
  })

  it('displays Reachable badge', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('Reachable')).toBeInTheDocument())
  })

  it('shows overview tab by default', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('What happened? Where? Why?')).toBeInTheDocument())
  })

  it('shows asset info in overview', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText(/Payment API.*PRODUCTION.*Team Alpha/)).toBeInTheDocument())
  })

  it('shows recommendation section', async () => {
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText('Recommendation')).toBeInTheDocument()
      expect(screen.getByText('Use parameterized queries')).toBeInTheDocument()
    })
  })

  it('shows code snippet in overview', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getAllByText(/SELECT \* FROM users/).length).toBeGreaterThanOrEqual(1))
  })

  it('shows AI Security Analyst section', async () => {
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText('AI Security Analyst')).toBeInTheDocument()
      expect(screen.getByText('String concatenation')).toBeInTheDocument()
      expect(screen.getByText('Data breach')).toBeInTheDocument()
      expect(screen.getByText('Use prepared statements')).toBeInTheDocument()
      expect(screen.getByText('Priority: P0')).toBeInTheDocument()
    })
  })

  it('shows fingerprint section', async () => {
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText('Fingerprint (Dedup)')).toBeInTheDocument()
      expect(screen.getByText('abc123def456')).toBeInTheDocument()
    })
  })

  it('switches to code tab on click', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('code', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('Code Path & Evidence')).toBeInTheDocument())
  })

  it('shows code path info in code tab', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('code', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText(/File:/)).toBeInTheDocument()
      expect(screen.getByText('src/auth/login.ts:42')).toBeInTheDocument()
      expect(screen.getByText('Function: authenticate')).toBeInTheDocument()
    })
  })

  it('switches to evidence tab on click', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('evidence', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('Evidence (hash, timestamp, chain of custody)')).toBeInTheDocument())
  })

  it('displays evidence items', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('evidence', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText(/HTTP_REQUEST/)).toBeInTheDocument())
  })

  it('switches to correlation tab on click', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('correlation', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText('Cross-Scanner Correlation')).toBeInTheDocument()
      expect(screen.getByText(/Related XSS/)).toBeInTheDocument()
    })
  })

  it('switches to ai tab on click', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('ai', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText('AI Fix Assistant')).toBeInTheDocument()
      expect(screen.getByText('What is wrong:')).toBeInTheDocument()
      expect(screen.getByText('Why it matters:')).toBeInTheDocument()
      expect(screen.getByText('Recommended design change:')).toBeInTheDocument()
    })
  })

  it('highlights active tab with indigo styling', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    const overviewBtn = screen.getByText('overview', { selector: 'button' })
    expect(overviewBtn.className).toContain('border-indigo-600')
  })

  it('hides Internet Exposed badge when internetExposed is false', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { attackPathCandidate: 'No', correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'XSS', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 40, riskLevel: 'MEDIUM', cvss: 6.1, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'XSS', assetName: 'Web App', environment: 'PRODUCTION', owner: 'Team Beta', filePath: 'src/app.ts', lineNumber: 10, functionName: 'render', dataFlow: 'HTTP → View', businessCriticality: 'MEDIUM', recommendation: 'Escape output', codeSnippet: '', fingerprint: 'def456', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByRole('heading', { name: 'XSS' })).toBeInTheDocument())
    expect(screen.queryByText('Internet Exposed')).not.toBeInTheDocument()
    expect(screen.queryByText('Reachable')).not.toBeInTheDocument()
  })

  it('shows AI loading state when ai data is null', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return new Promise(() => {})
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'AI Null Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('AI Null Test')).toBeInTheDocument())
    expect(screen.getByText('Loading AI analysis...')).toBeInTheDocument()
  })

  it('shows no evidence message when evidence list is empty', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'No Evidence Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('No Evidence Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('evidence', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('No evidence yet.')).toBeInTheDocument())
  })

  it('shows no correlated findings when correlation list is empty', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'No Correlation Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('No Correlation Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('correlation', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('No correlated findings on this asset yet.')).toBeInTheDocument())
  })

  it('shows code tab fallback when codeSnippet is empty', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'No Code Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', codeSnippet: '', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('No Code Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('code', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('// no snippet')).toBeInTheDocument())
  })

  it('shows no AI content in ai tab when ai is null', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return new Promise(() => {})
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'AI Tab Null Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('AI Tab Null Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('ai', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('AI Fix Assistant')).toBeInTheDocument())
    expect(screen.queryByText('What is wrong:')).not.toBeInTheDocument()
  })

  it('hides code snippet in overview when codeSnippet is falsy', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'No Code Snippet', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('No Code Snippet')).toBeInTheDocument())
    expect(screen.queryByText(/SELECT \* FROM users/)).not.toBeInTheDocument()
  })

  it('displays dash when slaDueAt is null', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'SLA Dash Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText('SLA Dash Test')).toBeInTheDocument()
      expect(screen.getByText(/SLA OK/)).toBeInTheDocument()
      expect(screen.getByText(/Due -/)).toBeInTheDocument()
    })
  })

  it('displays attack path candidate text in correlation tab', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('correlation', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText(/SAST \+ DAST \+ Asset exposure/)).toBeInTheDocument()
      expect(screen.getByText(/Yes/)).toBeInTheDocument()
    })
  })

  it('shows overview details with internet exposed text', async () => {
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText(/Internet exposed/)).toBeInTheDocument()
    })
  })

  it('navigates to code tab and shows call chain', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('code', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText(/Controller → Service → Repository/)).toBeInTheDocument()
      expect(screen.getByText(/Stack trace, HTTP request\/response/)).toBeInTheDocument()
    })
  })

  it('navigates to ai tab and shows full details', async () => {
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('SQL Injection')).toBeInTheDocument())
    fireEvent.click(screen.getByText('ai', { selector: 'button' }))
    await waitFor(() => {
      expect(screen.getByText('What is wrong:')).toBeInTheDocument()
      expect(screen.getByText('SQL injection found')).toBeInTheDocument()
      expect(screen.getByText('Affected components:')).toBeInTheDocument()
      expect(screen.getByText(/Payment API/)).toBeInTheDocument()
      expect(screen.getByText('Regression risk:')).toBeInTheDocument()
    })
  })

  it('handles null evidence data in evidence tab', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: null } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'Null Evidence Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('Null Evidence Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('evidence', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('No evidence yet.')).toBeInTheDocument())
  })

  it('handles null correlation data in correlation tab', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: null } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'Null Corr Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 50, riskLevel: 'MODERATE', cvss: 5.0, kev: false, severity: 'MEDIUM', confidence: 'MEDIUM', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('Null Corr Test')).toBeInTheDocument())
    fireEvent.click(screen.getByText('correlation', { selector: 'button' }))
    await waitFor(() => expect(screen.getByText('No correlated findings on this asset yet.')).toBeInTheDocument())
  })

  it('displays internet exposed text in overview when internetExposed is true', async () => {
    render(wrapWithRoute())
    await waitFor(() => {
      expect(screen.getByText(/Internet exposed/)).toBeInTheDocument()
    })
  })

  it('hides internet exposed text in overview when internetExposed is false', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/api/v1/ai/explain/1')) return Promise.resolve({ data: { success: true, data: { rootCause: 'Test', impact: 'Test', remediation: 'Test', codeFix: 'test', priority: 'P1', summary: 'Test', testRecommendation: 'Test' } } })
      if (url.includes('/api/v1/findings/1/evidence')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/api/v1/findings/1/correlation')) return Promise.resolve({ data: { success: true, data: { correlated: [] } } })
      if (url.includes('/api/v1/findings/1')) return Promise.resolve({ data: { success: true, data: { id: '1', findingId: 'FND-001', title: 'No Internet Test', cwe: 'CWE-79', owasp: 'A03', source: 'SEMGREP', riskScore: 30, riskLevel: 'LOW', cvss: 3.0, kev: false, severity: 'LOW', confidence: 'LOW', status: 'OPEN', internetExposed: false, reachable: false, description: 'Test', assetName: 'App', environment: 'DEV', owner: 'Team', filePath: 'src/test.ts', lineNumber: 1, functionName: 'test', dataFlow: 'HTTP', businessCriticality: 'LOW', recommendation: 'Fix', fingerprint: 'abc123', slaStatus: 'OK', slaDueAt: '2025-12-01T00:00:00Z' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrapWithRoute())
    await waitFor(() => expect(screen.getByText('No Internet Test')).toBeInTheDocument())
    const overviewDiv = screen.getByText(/How dangerous/)
    expect(overviewDiv.textContent).not.toContain('Internet exposed')
  })
})
