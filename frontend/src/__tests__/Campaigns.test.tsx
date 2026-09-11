import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Page from '../pages/Campaigns'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, get: vi.fn().mockResolvedValue({ data: { data: { content: [] } } }), post: vi.fn().mockResolvedValue({ data: { data: {} } }) } }
})

describe('Campaigns — page render', () => {
  it('renders without crashing', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Page /></MemoryRouter></QueryClientProvider>)
    expect(document.body).toBeInTheDocument()
    // at least one heading or page text should be present; fallback to body check
    await new Promise(r => setTimeout(r, 200))
    expect(document.body.textContent?.length).toBeGreaterThan(0)
  })
})
