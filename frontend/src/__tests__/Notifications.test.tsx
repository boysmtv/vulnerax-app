import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'n1', title: 'Critical vulnerability found', type: 'SEVERITY', severity: 'CRITICAL', read: false, createdAt: '2025-11-15T10:00:00Z' }, { id: 'n2', title: 'SLA breached', type: 'SLA_BREACH', severity: 'HIGH', read: true, createdAt: '2025-11-14T08:00:00Z' }] } } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Notifications from '../pages/Notifications'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Notifications', () => {
  beforeEach(() => { vi.clearAllMocks(); mockGet.mockImplementation((url: string) => { if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } }); if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'n1', title: 'Critical vulnerability found', type: 'SEVERITY', severity: 'CRITICAL', read: false, createdAt: '2025-11-15T10:00:00Z' }, { id: 'n2', title: 'SLA breached', type: 'SLA_BREACH', severity: 'HIGH', read: true, createdAt: '2025-11-14T08:00:00Z' }] } } }); return Promise.resolve({ data: { success: true, data: { content: [] } } }) }) })

  it('renders title and subtitle', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => {
      expect(screen.getByText('Notifications')).toBeInTheDocument()
      expect(screen.getByText(/Alerts.*Severity.*SLA Breach/)).toBeInTheDocument()
    })
  })

  it('displays table headers', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => {
      expect(screen.getByText('Title')).toBeInTheDocument()
      expect(screen.getByText('Type')).toBeInTheDocument()
      expect(screen.getByText('Severity')).toBeInTheDocument()
      expect(screen.getByText('Read')).toBeInTheDocument()
    })
  })

  it('displays notification data', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => {
      expect(screen.getByText('Critical vulnerability found')).toBeInTheDocument()
      expect(screen.getByText('SLA breached')).toBeInTheDocument()
      expect(screen.getByText('Severity')).toBeInTheDocument()
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      expect(screen.getByText('Unread')).toBeInTheDocument()
      expect(screen.getAllByText('Read').length).toBeGreaterThanOrEqual(1)
    })
  })

  it('displays record count', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => expect(screen.getByText('2 records')).toBeInTheDocument())
  })

  it('shows empty state when no notifications', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Notifications />))
    await waitFor(() => expect(screen.getByText('No data yet')).toBeInTheDocument())
  })

  it('displays project selector', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument())
  })

  it('renders read status for true and false', async () => {
    render(wrap(<Notifications />))
    await waitFor(() => {
      expect(screen.getByText('Unread')).toBeInTheDocument()
      expect(screen.getAllByText('Read').length).toBeGreaterThanOrEqual(2)
    })
  })

  it('renders createdAt with date when present and dash when absent', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/notifications')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'n1', title: 'Alert', type: 'SEVERITY', severity: 'HIGH', read: false, createdAt: '2025-11-15T10:00:00Z' }, { id: 'n2', title: 'Old Alert', type: 'SLA', severity: 'LOW', read: true, createdAt: null }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Notifications />))
    await waitFor(() => {
      expect(screen.getByText('Alert')).toBeInTheDocument()
      expect(screen.getByText('Old Alert')).toBeInTheDocument()
    })
    expect(screen.getAllByText('-').length).toBeGreaterThanOrEqual(1)
  })
})
