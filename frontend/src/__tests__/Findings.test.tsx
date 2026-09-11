import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Findings from '../pages/Findings'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn() } }
})

const mockFindings = {
  content: [
    { id: '1', findingId: 'FND-1001', title: 'SQL Injection via Unsanitized Input', severity: 'HIGH', status: 'OPEN', riskLevel: 'CRITICAL', riskScore: 85 },
    { id: '2', findingId: 'FND-1002', title: 'Broken Object Level Authorization', severity: 'CRITICAL', status: 'OPEN', riskLevel: 'CRITICAL', riskScore: 92 },
  ]
}

describe('Findings — Vulnerability Explorer', () => {
  it('renders findings explorer', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: mockFindings } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Findings /></MemoryRouter></QueryClientProvider>)
    // title may be Findings or Vulnerability Explorer
    const title = await screen.findByText(/Findings|Vulnerability/i)
    expect(title).toBeInTheDocument()
  })

  it('shows findings list', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: mockFindings } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><MemoryRouter><Findings /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText(/SQL Injection/i)).toBeInTheDocument()
    expect(await screen.findByText(/Broken Object Level/i)).toBeInTheDocument()
  })

  it('shows severity badges', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: mockFindings } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><MemoryRouter><Findings /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText('HIGH')).toBeInTheDocument()
    expect(await screen.findByText('CRITICAL')).toBeInTheDocument()
  })
})
