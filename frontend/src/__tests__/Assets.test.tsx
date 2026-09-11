import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Assets from '../pages/Assets'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } }
})

const mockAssets = [
  { id: '1', name: 'api.example.com', type: 'DOMAIN', criticality: 'HIGH', internetExposed: true, status: 'ACTIVE' },
  { id: '2', name: 'db01', type: 'DATABASE', criticality: 'CRITICAL', internetExposed: false, status: 'ACTIVE' },
]

describe('Assets — Asset Inventory', () => {
  it('renders asset inventory page', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: { content: mockAssets } } })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><Assets /></QueryClientProvider>)
    expect(await screen.findByText(/Asset Inventory/i)).toBeInTheDocument()
  })

  it('displays assets from api', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: { content: mockAssets } } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><Assets /></QueryClientProvider>)
    expect(await screen.findByText('api.example.com')).toBeInTheDocument()
    expect(await screen.findByText('db01')).toBeInTheDocument()
  })

  it('shows discover button', async () => {
    vi.mocked(client.api.get).mockResolvedValue({ data: { data: { content: [] } } })
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><Assets /></QueryClientProvider>)
    await waitFor(() => expect(screen.getByText(/Asset Inventory/i)).toBeInTheDocument())
    const discovers = screen.getAllByText(/Discover/i)
    expect(discovers.length).toBeGreaterThan(0)
  })
})
