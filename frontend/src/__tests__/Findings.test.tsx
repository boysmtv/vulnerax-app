import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { securityScore: 75, critical: 5, high: 20, totalAssets: 42, kev: 2, internetExposed: 3, slaBreached: 1, bySeverity: { CRITICAL: 5, HIGH: 20, MEDIUM: 30, LOW: 40 } } } })
    return Promise.resolve({ data: { success: true, data: { content: [{ id: '1', name: 'Test', status: 'ACTIVE', severity: 'HIGH', title: 'Test Finding', findingId: 'FND-001', cvss: 7.5, cwe: 'CWE-79', source: 'SEMGREP', type: 'SAST', riskScore: 8.0, riskLevel: 'HIGH', owasp: 'A03' }], totalElements: 1, totalPages: 1 } } })
  }),
  mockPut: vi.fn().mockResolvedValue({ data: { success: true } }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }), put: mockPut },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Findings from '../pages/Findings'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Findings', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders title and subtitle', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('Vulnerability Explorer')).toBeInTheDocument())
    expect(screen.getByText(/assets/)).toBeInTheDocument()
  })

  it('renders search input', () => {
    render(wrap(<Findings />))
    expect(screen.getByPlaceholderText(/Search CVE/)).toBeInTheDocument()
  })

  it('renders severity filter dropdown', () => {
    render(wrap(<Findings />))
    expect(screen.getByDisplayValue('All severity')).toBeInTheDocument()
  })

  it('renders status filter dropdown', () => {
    render(wrap(<Findings />))
    expect(screen.getByDisplayValue('All status')).toBeInTheDocument()
  })

  it('displays finding rows in table', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
  })

  it('displays finding severity badge', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('HIGH')).toBeInTheDocument())
  })

  it('displays finding risk score', async () => {
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument()
      expect(screen.getByText('Risk')).toBeInTheDocument()
    })
  })

  it('displays CWE and OWASP info', async () => {
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText(/CWE-79/)).toBeInTheDocument()
      expect(screen.getByText(/A03/)).toBeInTheDocument()
    })
  })

  it('displays source', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText(/SEMGREP/)).toBeInTheDocument())
  })

  it('clicks Resolve button and calls api.put', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('Resolve')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Resolve'))
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/api/v1/findings/1/status', { status: 'RESOLVED', comment: 'via UI' }))
  })

  it('clicks FP button and calls api.put', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FP')).toBeInTheDocument())
    fireEvent.click(screen.getByText('FP'))
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/api/v1/findings/1/status', { status: 'FALSE_POSITIVE', comment: 'via UI' }))
  })

  it('changes severity filter', async () => {
    render(wrap(<Findings />))
    const severitySelect = screen.getByDisplayValue('All severity')
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } })
    expect(severitySelect).toHaveValue('CRITICAL')
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/api/v1/findings', expect.objectContaining({ params: expect.objectContaining({ severity: 'CRITICAL' }) })))
  })

  it('changes status filter', async () => {
    render(wrap(<Findings />))
    const statusSelect = screen.getByDisplayValue('All status')
    fireEvent.change(statusSelect, { target: { value: 'OPEN' } })
    expect(statusSelect).toHaveValue('OPEN')
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/api/v1/findings', expect.objectContaining({ params: expect.objectContaining({ status: 'OPEN' }) })))
  })

  it('search input filters findings by title', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
    const searchInput = screen.getByPlaceholderText(/Search CVE/)
    fireEvent.change(searchInput, { target: { value: 'xyz' } })
    expect(searchInput).toHaveValue('xyz')
    await waitFor(() => expect(screen.getByText(/No findings/)).toBeInTheDocument())
  })

  it('search input filters by findingId', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Search CVE/), { target: { value: 'FND-001' } })
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
  })

  it('shows empty state when no findings match filter', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText(/No findings\. Run a scan/)).toBeInTheDocument())
  })

  it('links to finding detail page', async () => {
    render(wrap(<Findings />))
    await waitFor(() => {
      const link = screen.getByText('FND-001 — Test Finding')
      expect(link.closest('a')).toHaveAttribute('href', '/findings/1')
    })
  })

  it('renders loading state', () => {
    mockGet.mockReturnValueOnce(new Promise(() => {}))
    render(wrap(<Findings />))
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('displays column headers', async () => {
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('Finding')).toBeInTheDocument()
      expect(screen.getByText('Severity')).toBeInTheDocument()
      expect(screen.getByText('Risk')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()
      expect(screen.getByText('Actions')).toBeInTheDocument()
    })
  })

  it('displays KEV badge when kev is true', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '2', name: 'Test', status: 'OPEN', severity: 'CRITICAL', title: 'Critical Vuln', findingId: 'FND-002', cvss: 9.8, cwe: 'CWE-89', source: 'SEMGREP', riskScore: 95, riskLevel: 'CRITICAL', owasp: 'A03', kev: true, internetExposed: true }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('KEV')).toBeInTheDocument()
      expect(screen.getByText('Exposed')).toBeInTheDocument()
    })
  })

  it('displays fallback riskScore when riskScore is null', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '3', name: 'Test', status: 'OPEN', severity: 'MEDIUM', title: 'Medium Vuln', findingId: 'FND-003', cvss: 5.0, cwe: 'CWE-79', source: 'DAST', riskScore: null, riskLevel: 'MODERATE', owasp: 'A07' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-003 — Medium Vuln')).toBeInTheDocument()
    })
  })

  it('displays fallback for unknown severity color', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '4', name: 'Test', status: 'OPEN', severity: 'INFO', title: 'Info Vuln', findingId: 'FND-004', cvss: 1.0, source: 'MANUAL', riskScore: 2, riskLevel: 'LOW', owasp: 'A01' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-004 — Info Vuln')).toBeInTheDocument()
    })
  })

  it('search filters by CWE when q matches cwe', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Search CVE/), { target: { value: 'CWE-79' } })
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
  })

  it('search filters by findingId match shows results', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Search CVE/), { target: { value: 'FND' } })
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
  })

  it('search filters by title match', async () => {
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Search CVE/), { target: { value: 'Test Finding' } })
    await waitFor(() => expect(screen.getByText('FND-001 — Test Finding')).toBeInTheDocument())
  })

  it('displays fallback bg-slate-200 for unknown severity color', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '5', name: 'Test', status: 'OPEN', severity: 'UNKNOWN', title: 'Unknown Sev', findingId: 'FND-005', cvss: 3.0, source: 'MANUAL', riskScore: 10, riskLevel: 'LOW', owasp: 'A01' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-005 — Unknown Sev')).toBeInTheDocument()
      const badge = screen.getByText('UNKNOWN')
      expect(badge.className).toContain('bg-slate-200')
    })
  })

  it('displays fallback empty class for unknown riskLevel', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '6', name: 'Test', status: 'OPEN', severity: 'LOW', title: 'Unknown Risk', findingId: 'FND-006', cvss: 2.0, source: 'MANUAL', riskScore: 5, riskLevel: 'VERY_LOW', owasp: 'A01' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-006 — Unknown Risk')).toBeInTheDocument()
      expect(screen.getByText('VERY_LOW')).toBeInTheDocument()
    })
  })

  it('displays finding with no cwe field', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '7', name: 'Test', status: 'OPEN', severity: 'HIGH', title: 'No CWE', findingId: 'FND-007', cvss: 7.0, source: 'DAST', riskScore: 60, riskLevel: 'HIGH', owasp: 'A05' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => {
      expect(screen.getByText('FND-007 — No CWE')).toBeInTheDocument()
    })
  })

  it('search filters by cwe fallback when finding has no cwe and q is set', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/findings')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '7', name: 'Test', status: 'OPEN', severity: 'HIGH', title: 'No CWE Vuln', findingId: 'FND-007', cvss: 7.0, source: 'DAST', riskScore: 60, riskLevel: 'HIGH', owasp: 'A05' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Findings />))
    await waitFor(() => expect(screen.getByText('FND-007 — No CWE Vuln')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Search CVE/), { target: { value: 'xyz' } })
    await waitFor(() => expect(screen.getByText(/No findings/)).toBeInTheDocument())
  })
})
