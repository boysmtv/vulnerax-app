import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' }] } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }),
  mockPost: vi.fn().mockResolvedValue({ data: { success: true } }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Coverage from '../pages/Coverage'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Coverage', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders title and subtitle', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Security Coverage')).toBeInTheDocument()
      expect(screen.getByText(/SAST.*SCA.*Secrets.*DAST/)).toBeInTheDocument()
    })
  })

  it('displays project selector and Create Demo button', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument()
      expect(screen.getByText('Create Demo')).toBeInTheDocument()
    })
  })

  it('clicks Create Demo and calls api.post', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('option', { name: 'Test Project' })).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/coverage', expect.objectContaining({ projectId: 'p1' })))
  })

  it('displays coverage data', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText(/SAST.*TESTED.*85/)).toBeInTheDocument())
  })

  it('shows empty state when no coverage data', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument())
  })

  it('displays API info footer', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText(/API: GET \/api\/v1\/coverage/)).toBeInTheDocument())
  })

  it('changes project selector', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('handles Create Demo error', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    mockPost.mockRejectedValueOnce({ response: { data: { message: 'Failed to create' } } })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => {
      expect(alertSpy).toHaveBeenCalledWith('Failed to create')
    })
    alertSpy.mockRestore()
  })

  it('displays coverage data as JSON in pre element', async () => {
    render(wrap(<Coverage />))
    await waitFor(() => {
      const pre = document.querySelector('pre')
      expect(pre).toBeInTheDocument()
    })
  })
})
