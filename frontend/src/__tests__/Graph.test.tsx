import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [{ id: 'ap1', entryPoint: 'Internet', weakness: 'SQL Injection', asset: 'Payment API', risk: 92, riskLevel: 'CRITICAL', chain: ['Internet', 'API Gateway', 'Payment DB'], impact: 'Full DB compromise', mitigation: 'Parameterized queries' }] } })
    if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [{ id: 'n1', label: 'Payment API', type: 'ASSET', assetType: 'API' }, { id: 'n2', label: 'SQL Injection', type: 'FINDING', severity: 'CRITICAL' }], edges: [{ from: 'n1', to: 'n2', label: 'HAS' }], stats: { nodes: 2, edges: 1 } } } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Graph from '../pages/Graph'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Graph', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders title and subtitle', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText('Security Graph & Attack Path')).toBeInTheDocument()
      expect(screen.getByText(/Asset.*Component.*Dependency/)).toBeInTheDocument()
    })
  })

  it('displays project selector', async () => {
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument())
  })

  it('displays graph nodes and edges', async () => {
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByRole('option', { name: 'Test Project' })).toBeInTheDocument())
    await waitFor(() => {
      expect(screen.getByText('Payment API')).toBeInTheDocument()
      expect(screen.getAllByText('SQL Injection').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText(/Nodes: 2/)).toBeInTheDocument()
      expect(screen.getByText(/Edges: 1/)).toBeInTheDocument()
    })
  })

  it('displays attack path data', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/Entry: Internet/)).toBeInTheDocument()
      expect(screen.getByText('Full DB compromise')).toBeInTheDocument()
      expect(screen.getByText('Parameterized queries')).toBeInTheDocument()
    })
  })

  it('displays knowledge graph relationships', async () => {
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByText(/APPLICATION USES REPOSITORY/)).toBeInTheDocument())
  })

  it('displays exploitation disclaimer', async () => {
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByText(/Platform does not do uncontrolled autonomous exploitation/)).toBeInTheDocument())
  })

  it('shows empty state when no attack paths', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByText(/No attack paths yet/)).toBeInTheDocument())
  })

  it('changes project selector', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('displays attack path chain elements', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText('Internet')).toBeInTheDocument()
      expect(screen.getByText('API Gateway')).toBeInTheDocument()
      expect(screen.getByText('Payment DB')).toBeInTheDocument()
    })
  })

  it('displays risk level in attack path', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/Risk 92.*CRITICAL/)).toBeInTheDocument()
    })
  })

  it('displays edge labels', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/HAS/)).toBeInTheDocument()
    })
  })

  it('displays node type information', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/ASSET API/)).toBeInTheDocument()
    })
  })

  it('displays finding severity in node', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/FINDING CRITICAL/)).toBeInTheDocument()
    })
  })

  it('renders graph heading', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/Attack Graph.*interactive/)).toBeInTheDocument()
    })
  })

  it('renders attack paths heading', async () => {
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/Attack Paths.*Entry Point/)).toBeInTheDocument()
    })
  })

  it('displays HIGH severity finding node', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [{ id: 'n1', label: 'XSS Bug', type: 'FINDING', severity: 'HIGH' }], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText('XSS Bug')).toBeInTheDocument()
      expect(screen.getByText(/FINDING HIGH/)).toBeInTheDocument()
    })
  })

  it('displays MEDIUM severity finding node', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [{ id: 'n1', label: 'Info Leak', type: 'FINDING', severity: 'MEDIUM' }], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText('Info Leak')).toBeInTheDocument()
      expect(screen.getByText(/FINDING MEDIUM/)).toBeInTheDocument()
    })
  })

  it('displays more than 10 edges with overflow message', async () => {
    const manyEdges = Array.from({ length: 15 }, (_, i) => ({ from: `n${i}`, to: `n${i + 1}`, label: `E${i}` }))
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: manyEdges, stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/\+5 more edges/)).toBeInTheDocument()
    })
  })

  it('handles non-array paths response', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: { items: [] } } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/No attack paths yet/)).toBeInTheDocument()
    })
  })

  it('displays attack path without chain', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/graph/attack-paths')) return Promise.resolve({ data: { success: true, data: [{ id: 'ap1', entryPoint: 'Network', weakness: 'Weak Auth', asset: 'Service', risk: 60, riskLevel: 'MEDIUM', impact: 'Partial access', mitigation: 'MFA' }] } })
      if (url.includes('/graph')) return Promise.resolve({ data: { success: true, data: { nodes: [], edges: [], stats: {} } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Graph />))
    await waitFor(() => {
      expect(screen.getByText(/Entry: Network/)).toBeInTheDocument()
      expect(screen.getByText('Weak Auth')).toBeInTheDocument()
    })
  })
})
