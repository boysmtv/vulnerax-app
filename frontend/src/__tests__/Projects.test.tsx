import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/organizations')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'org1', name: 'Acme Corp', slug: 'acme', tier: 'ENTERPRISE' }] } } })
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Digital Banking', description: 'Core banking app', criticality: 'HIGH', status: 'ACTIVE', businessUnit: 'Retail' }] } } })
    if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }),
  mockPost: vi.fn().mockResolvedValue({ data: { success: true, data: { id: 'ws1' } } }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Projects from '../pages/Projects'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Projects', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders title and subtitle', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText('Organization & Project Hierarchy')).toBeInTheDocument()
      expect(screen.getByText(/Organization.*Business Unit.*Team.*Workspace.*Project/)).toBeInTheDocument()
    })
  })

  it('displays organization data', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument()
      expect(screen.getByText(/acme.*ENTERPRISE/)).toBeInTheDocument()
    })
  })

  it('creates org via api.post', async () => {
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByText('Acme Corp')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/New org name/), { target: { value: 'New Org' } })
    fireEvent.click(screen.getByText('Create'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/organizations', expect.objectContaining({ name: 'New Org' })))
  })

  it('fills project form and submits', async () => {
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByText('Acme Corp')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Project name/), { target: { value: 'New Banking App' } })
    fireEvent.change(screen.getByPlaceholderText(/Description/), { target: { value: 'Description text' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects', expect.objectContaining({ name: 'New Banking App', description: 'Description text', criticality: 'HIGH' })))
  })

  it('displays existing projects list', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getAllByText('Digital Banking').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText(/Core banking app.*HIGH.*Retail/)).toBeInTheDocument()
      expect(screen.getByText('ACTIVE')).toBeInTheDocument()
    })
  })

  it('changes criticality select', async () => {
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create Project' })).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('HIGH'), { target: { value: 'CRITICAL' } })
    expect(screen.getByDisplayValue('CRITICAL')).toBeInTheDocument()
  })

  it('displays example assessment section', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText(/Example Final Assessment/)).toBeInTheDocument()
      expect(screen.getByText(/Authorization weakness/)).toBeInTheDocument()
    })
  })

  it('creates project with workspaceId when workspaces exist', async () => {
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByText('Acme Corp')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Project name/), { target: { value: 'New App' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }))
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith('/api/v1/projects', expect.objectContaining({ name: 'New App', workspaceId: 'ws1', organizationId: 'org1' }))
    })
  })

  it('displays project status badge', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText('ACTIVE')).toBeInTheDocument()
    })
  })

  it('displays project description and criticality', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText(/Core banking app.*HIGH.*Retail/)).toBeInTheDocument()
    })
  })

  it('displays organization slug and tier', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText(/acme.*ENTERPRISE/)).toBeInTheDocument()
    })
  })

  it('displays example findings', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText(/CRITICAL 3/)).toBeInTheDocument()
      expect(screen.getByText(/HIGH 17/)).toBeInTheDocument()
    })
  })

  it('displays example priority finding', async () => {
    render(wrap(<Projects />))
    await waitFor(() => {
      expect(screen.getByText(/Vulnerable Dependency CVSS 9.8/)).toBeInTheDocument()
    })
  })

  it('creates workspace when no workspaces exist', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/organizations')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'org1', name: 'Acme Corp', slug: 'acme', tier: 'ENTERPRISE' }] } } })
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Digital Banking', description: 'Core banking app', criticality: 'HIGH', status: 'ACTIVE', businessUnit: 'Retail' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { id: 'ws-new' } } })
      return Promise.resolve({ data: { success: true, data: { id: 'p-new' } } })
    })
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByText('Acme Corp')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Project name/), { target: { value: 'New App' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }))
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith('/api/v1/workspaces', expect.objectContaining({ name: 'Primary', organizationId: 'org1' }))
    })
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith('/api/v1/projects', expect.objectContaining({ name: 'New App', workspaceId: 'ws-new', organizationId: 'org1' }))
    })
  })

  it('alerts when no org available for project creation', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/organizations')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<Projects />))
    await waitFor(() => expect(screen.getByText('Organization & Project Hierarchy')).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/Project name/), { target: { value: 'New App' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }))
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith('Create org first'))
    alertSpy.mockRestore()
  })
})
