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
    expect(screen.getByText(/Filter by Severity/)).toBeInTheDocument()
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
})
