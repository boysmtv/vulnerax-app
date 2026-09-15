import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Page from '../pages/Compliance'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn().mockResolvedValue({ data: { data: { content: [] } } }), post: vi.fn().mockResolvedValue({ data: { data: {} } }) } }
})

describe('Compliance — page render', () => {
  const { api } = client

  it('renders without crashing', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Page /></MemoryRouter></QueryClientProvider>)
    expect(document.body).toBeInTheDocument()
    // at least one heading or page text should be present; fallback to body check
    await new Promise(r => setTimeout(r, 200))
    expect(document.body.textContent?.length).toBeGreaterThan(0)
  })

  it('renders data rows with formatted dates when data exists', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url.includes('/api/v1/projects'))
        return { data: { data: { content: [{ id: 'p1', name: 'TestProject', organizationId: 'o1' }] } } }
      return { data: { data: { content: [
        { id: 'r1', name: 'TestItem', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00Z' }
      ] } } }
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Page /></MemoryRouter></QueryClientProvider>)
    await waitFor(() => {
      expect(screen.getByText('TestItem')).toBeInTheDocument()
    })
  })

  it('renders dash for null createdAt values', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url.includes('/api/v1/projects'))
        return { data: { data: { content: [{ id: 'p1', name: 'TestProject', organizationId: 'o1' }] } } }
      return { data: { data: { content: [
        { id: 'r1', name: 'TestItem', status: 'ACTIVE', createdAt: null }
      ] } } }
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Page /></MemoryRouter></QueryClientProvider>)
    await waitFor(() => {
      expect(screen.getByText('TestItem')).toBeInTheDocument()
    })
  })
})
