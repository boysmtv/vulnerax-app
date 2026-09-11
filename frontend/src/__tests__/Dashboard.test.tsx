import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Dashboard from '../pages/Dashboard'
import * as clientModule from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn() } }
})

describe('Dashboard — Security Command Center', () => {
  it('renders Security Command Center title', async () => {
    vi.mocked(clientModule.api.get).mockResolvedValue({ data: { data: { securityScore: 74, critical: 3, high: 17, totalAssets: 247 } } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><Dashboard /></QueryClientProvider>)
    expect(await screen.findByText(/Security Command Center/i)).toBeInTheDocument()
    expect(screen.getByText(/Security Score/i)).toBeInTheDocument()
  })

  it('shows stats fallback when api empty', async () => {
    vi.mocked(clientModule.api.get).mockResolvedValue({ data: { data: null } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><Dashboard /></QueryClientProvider>)
    expect(await screen.findByText(/Security Command Center/i)).toBeInTheDocument()
    // fallback renders at least one chart title
    expect(screen.getByText(/Findings by Severity/i)).toBeInTheDocument()
  })

  it('shows Generate Report and New Assessment links', async () => {
    vi.mocked(clientModule.api.get).mockResolvedValue({ data: { data: {} } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><Dashboard /></QueryClientProvider>)
    expect(await screen.findByText(/Generate Report/i)).toBeInTheDocument()
    expect(screen.getByText(/New Assessment/i)).toBeInTheDocument()
  })
})
