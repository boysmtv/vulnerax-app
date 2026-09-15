import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
    if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 10, internetExposed: 3, discoveryDelta: { newLast24h: 2 }, byType: { API: 5, DOMAIN: 3, SHADOW: 1 } } } })
    if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'Payment API', identifier: 'api.acme.com', technology: 'Node.js', type: 'API', environment: 'PROD', criticality: 'CRITICAL', internetExposed: true, owner: 'Team Alpha' }], totalElements: 1 } } })
    return Promise.resolve({ data: { success: true, data: { content: [], totalElements: 0 } } })
  }),
  mockPost: vi.fn().mockResolvedValue({ data: { success: true } }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Assets from '../pages/Assets'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Assets', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders Asset Inventory title', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
  })

  it('displays asset table with data', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Payment API')).toBeInTheDocument()
      expect(screen.getByText('Asset')).toBeInTheDocument()
      expect(screen.getByText('Type')).toBeInTheDocument()
    })
  })

  it('displays asset type, criticality, and exposure badges', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('API', { selector: '.border' })).toBeInTheDocument()
      expect(screen.getByText('CRITICAL', { selector: '.rounded' })).toBeInTheDocument()
      expect(screen.getByText('Exposed')).toBeInTheDocument()
    })
  })

  it('toggles create form when clicking New Asset', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('New Asset'))
    expect(screen.getByText('Register Asset')).toBeInTheDocument()
    fireEvent.click(screen.getByText('New Asset'))
    expect(screen.queryByText('Register Asset')).not.toBeInTheDocument()
  })

  it('fills create form and submits', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('New Asset'))
    fireEvent.change(screen.getByPlaceholderText(/Name.*Payment API/), { target: { value: 'New API' } })
    fireEvent.change(screen.getByPlaceholderText(/Identifier/), { target: { value: 'new.api.com' } })
    fireEvent.click(screen.getByText('Create').closest('button')!)
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/assets', expect.objectContaining({ name: 'New API', type: 'API', identifier: 'new.api.com' })))
  })

  it('clicks Discover button and calls api.post', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('option', { name: 'Test Project' })).toBeInTheDocument())
    fireEvent.click(screen.getByText('Discover'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/assets/discover', null, expect.objectContaining({ params: expect.objectContaining({ projectId: 'p1', source: 'MANUAL' }) })))
  })

  it('displays stats cards', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Total Assets')).toBeInTheDocument()
      expect(screen.getByText('Internet Exposed')).toBeInTheDocument()
      expect(screen.getByText('New (24h)')).toBeInTheDocument()
    })
  })

  it('changes type filter', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByDisplayValue('All types')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('All types'), { target: { value: 'API' } })
    expect(screen.getByDisplayValue('API')).toBeInTheDocument()
  })

  it('shows empty state when no assets', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/assets') && !url.includes('/stats')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText(/No assets for this project/)).toBeInTheDocument())
  })

  it('displays project selector', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument())
  })

  it('fills all form fields in create form', async () => {
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('New Asset'))
    fireEvent.change(screen.getByPlaceholderText(/Name.*Payment API/), { target: { value: 'New Asset' } })
    fireEvent.change(screen.getByPlaceholderText(/Identifier/), { target: { value: 'new.example.com' } })
    fireEvent.change(screen.getByPlaceholderText(/Technology/), { target: { value: 'Python' } })
    const typeSelect = screen.getByDisplayValue('API')
    fireEvent.change(typeSelect, { target: { value: 'DOMAIN' } })
    const critSelect = screen.getByDisplayValue('MEDIUM')
    fireEvent.change(critSelect, { target: { value: 'HIGH' } })
    const checkbox = screen.getByRole('checkbox')
    fireEvent.click(checkbox)
    fireEvent.click(screen.getByText('Create').closest('button')!)
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/assets', expect.objectContaining({
      name: 'New Asset',
      type: 'DOMAIN',
      identifier: 'new.example.com',
      technology: 'Python',
      criticality: 'HIGH',
      internetExposed: true,
    })))
  })

  it('displays asset owner column', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Team Alpha')).toBeInTheDocument()
    })
  })

  it('displays asset environment column', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('PROD')).toBeInTheDocument()
    })
  })

  it('displays Shadow / Unknown stat card', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Shadow / Unknown')).toBeInTheDocument()
    })
  })

  it('changes project selector', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A', organizationId: 'org1' }, { id: 'p2', name: 'Project B', organizationId: 'org2' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 0, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('renders all type filter options', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByDisplayValue('All types')).toBeInTheDocument()
    })
    const typeSelect = screen.getByDisplayValue('All types')
    fireEvent.change(typeSelect, { target: { value: 'REPOSITORY' } })
    expect(screen.getByDisplayValue('REPOSITORY')).toBeInTheDocument()
  })

  it('displays asset technology in table', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText(/Node\.js/)).toBeInTheDocument()
    })
  })

  it('displays asset identifier in table', async () => {
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText(/api\.acme\.com/)).toBeInTheDocument()
    })
  })

  it('alerts when no project available on create', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Asset Inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('New Asset'))
    fireEvent.click(screen.getByText('Create').closest('button')!)
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith('Create project first'))
    alertSpy.mockRestore()
  })

  it('displays MEDIUM criticality badge', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 1, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'Internal API', identifier: 'api.internal', technology: 'Java', type: 'API', environment: 'DEV', criticality: 'MEDIUM', internetExposed: false, owner: 'Team Beta' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Internal API')).toBeInTheDocument()
      expect(screen.getByText('Internal')).toBeInTheDocument()
    })
  })

  it('displays LOW criticality badge', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 1, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'Test Asset', identifier: 'test', technology: 'Go', type: 'DOMAIN', criticality: 'LOW', internetExposed: false, team: 'QA' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('LOW')).toBeInTheDocument()
      expect(screen.getByText('Internal')).toBeInTheDocument()
      expect(screen.getByText('QA')).toBeInTheDocument()
    })
  })

  it('displays stats with zero delta values', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 0, internetExposed: 0, discoveryDelta: { newLast24h: 0 }, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('Total Assets')).toBeInTheDocument()
      expect(screen.getByText('Internet Exposed')).toBeInTheDocument()
    })
  })

  it('displays stats without discoveryDelta', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 5, internetExposed: 1 } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
      expect(screen.getByText('1')).toBeInTheDocument()
    })
  })

  it('displays HIGH criticality badge', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 1, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'High Asset', identifier: 'high.test', type: 'API', criticality: 'HIGH', internetExposed: false }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('HIGH')).toBeInTheDocument()
      expect(screen.getByText('Internal')).toBeInTheDocument()
    })
  })

  it('displays asset with team instead of owner', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 1, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'Team Asset', identifier: 'team.test', type: 'API', criticality: 'MEDIUM', internetExposed: false, team: 'Backend Team' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => expect(screen.getByText('Backend Team')).toBeInTheDocument())
  })

  it('displays dash when no owner or team', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      if (url.includes('/assets/stats')) return Promise.resolve({ data: { success: true, data: { total: 1, internetExposed: 0, discoveryDelta: {}, byType: {} } } })
      if (url.includes('/assets')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'a1', name: 'No Owner Asset', identifier: 'noowner.test', type: 'DOMAIN', criticality: 'LOW', internetExposed: false }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Assets />))
    await waitFor(() => {
      expect(screen.getByText('No Owner Asset')).toBeInTheDocument()
      expect(screen.getByText('-')).toBeInTheDocument()
    })
  })
})
