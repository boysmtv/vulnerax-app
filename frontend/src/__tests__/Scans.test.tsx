import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Scans from '../pages/Scans'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } }
})

describe('Scans — Scan Center Orchestrator', () => {
  it('renders scan center', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: { content: [], id: '1', name: 'Test Project' } } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><Scans /></QueryClientProvider>)
    expect(await screen.findByText('Scan Center')).toBeInTheDocument()
    expect(screen.getByText('Scan Orchestrator')).toBeInTheDocument()
  })

  it('shows scans list when data present', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: { content: [{ id: '1', scannerType: 'SEMGREP', status: 'COMPLETED', target: 'app.jar' }] } } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><Scans /></QueryClientProvider>)
    expect(await screen.findByText(/SEMGREP/i)).toBeInTheDocument()
  })
})
