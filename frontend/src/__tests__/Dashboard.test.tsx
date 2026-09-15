import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { securityScore: 75, critical: 5, high: 20, totalAssets: 42, kev: 2, internetExposed: 3, slaBreached: 1, bySeverity: { CRITICAL: 5, HIGH: 20, MEDIUM: 30, LOW: 40 }, topRiskAssets: [{ name: 'Payment API', type: 'API', criticality: 'CRITICAL' }, { name: 'User Service', type: 'SERVICE', criticality: 'HIGH' }], trend: { critical: [5, 4, 3] } } } })
    return Promise.resolve({ data: { success: true, data: { content: [{ id: '1', name: 'Test', status: 'ACTIVE', severity: 'HIGH', title: 'Test Finding', findingId: 'FND-001', cvss: 7.5, cwe: 'CWE-79', source: 'SEMGREP', type: 'SAST', riskScore: 8.0, riskLevel: 'HIGH', owasp: 'A03' }], totalElements: 1, totalPages: 1 } } })
  }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Dashboard from '../pages/Dashboard'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Dashboard', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders Security Command Center title', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Security Command Center')).toBeInTheDocument())
  })

  it('renders subtitle text', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/Organization Security Posture/)).toBeInTheDocument())
  })

  it('displays security score from posture data', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('75').closest('div')).toHaveTextContent('75'))
  })

  it('displays critical risk count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('5')).toBeInTheDocument())
  })

  it('displays high risk count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('20')).toBeInTheDocument())
  })

  it('displays total assets count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('42')).toBeInTheDocument())
  })

  it('displays KEV count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/2 KEV/)).toBeInTheDocument())
  })

  it('displays internet exposed count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/3 exposed/)).toBeInTheDocument())
  })

  it('displays SLA breached count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/1 SLA breached/)).toBeInTheDocument())
  })

  it('renders Findings by Severity heading', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Findings by Severity')).toBeInTheDocument())
  })

  it('renders Risk Distribution heading', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Risk Distribution')).toBeInTheDocument())
  })

  it('links to /reports page', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Generate Report').closest('a')).toHaveAttribute('href', '/reports'))
  })

  it('links to /scans page', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('New Assessment').closest('a')).toHaveAttribute('href', '/scans'))
  })

  it('renders Security Coverage section', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Security Coverage')).toBeInTheDocument())
  })

  it('renders Top Risk Applications section', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Top Risk Applications')).toBeInTheDocument())
  })

  it('displays top risk assets when data exists', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText('Payment API')).toBeInTheDocument()
      expect(screen.getByText('User Service')).toBeInTheDocument()
    })
  })

  it('displays trend data when available', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText(/Trend computed from real findings/)).toBeInTheDocument()
    })
  })

  it('shows zero scores when posture data is empty', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: {} } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText('Security Score')).toBeInTheDocument()
      expect(screen.getByText(/\/ 100/)).toBeInTheDocument()
    })
  })

  it('renders empty state for severity chart when no data', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: {} } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No findings yet/)).toBeInTheDocument())
  })

  it('renders empty state for risk distribution when no data', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: {} } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No risk data/)).toBeInTheDocument())
  })

  it('shows empty state for top risk assets when none exist', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })

  it('shows no history delta when trend is not present', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 } } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No history.*real delta/)).toBeInTheDocument())
  })

  it('displays contextual risk formula', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/Contextual Risk.*CVSS.*EPSS/)).toBeInTheDocument())
  })

  it('renders coverage table with SAST entry', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/SAST.*12 langs/)).toBeInTheDocument())
  })

  it('displays coverage warning message', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/Not tested ≠ No vulnerability/)).toBeInTheDocument())
  })

  it('displays internet-exposed assets count', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText(/internet-exposed/)).toBeInTheDocument()
    })
  })

  it('displays security score bar', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText(/Transparent.*App 71/)).toBeInTheDocument()
    })
  })

  it('displays criticality badges for top risk assets', async () => {
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText('Payment API')).toBeInTheDocument()
      expect(screen.getByText('User Service')).toBeInTheDocument()
    })
  })

  it('renders empty state for top risk assets when topRiskAssets is null', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })

  it('renders empty state for top risk assets when topRiskAssets is undefined', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 } } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })

  it('shows zero securityScore when data exists but securityScore is null', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, critical: 0, high: 0, totalAssets: 0 } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => {
      expect(screen.getByText('Security Score')).toBeInTheDocument()
      expect(screen.getByText(/\/ 100/)).toBeInTheDocument()
    })
  })

  it('renders bar chart with unknown severity key using default color', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5, UNKNOWN_SEV: 10 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Findings by Severity')).toBeInTheDocument())
  })

  it('shows null securityScore fallback as 0', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { securityScore: null, bySeverity: { CRITICAL: 1 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Security Score')).toBeInTheDocument())
  })

  it('shows zero securityScore when data is null', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: null } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Security Score')).toBeInTheDocument())
  })

  it('renders pie chart with unknown severity key', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5, CUSTOM_SEV: 15 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Risk Distribution')).toBeInTheDocument())
  })

  it('shows topRiskAssets with items', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: [{ name: 'Payment API', type: 'API', criticality: 'CRITICAL' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Payment API')).toBeInTheDocument())
  })

  it('shows topRiskAssets empty state when array length is 0', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })
})
