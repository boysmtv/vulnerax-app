import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { securityScore: 75 } } })
    if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 's1', scannerType: 'SAST', target: 'https://github.com/acme/app', profile: 'STANDARD', status: 'COMPLETED', findingsCount: 12, durationMs: 30000, createdAt: '2025-11-15T10:00:00Z', initiatedBy: 'admin@vulnerax.io' }] } } })
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

import Scans from '../pages/Scans'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Scans', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders Scan Center title and subtitle', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('Scan Center')).toBeInTheDocument()
      expect(screen.getByText(/Queued.*Running.*Completed.*Failed/)).toBeInTheDocument()
    })
  })

  it('displays project selector', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument())
  })

  it('displays scannerType dropdown and changes to DAST', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByDisplayValue('SAST')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('SAST'), { target: { value: 'DAST' } })
    expect(screen.getByDisplayValue('DAST')).toBeInTheDocument()
  })

  it('changes scannerType to all values', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByDisplayValue('SAST')).toBeInTheDocument())
    for (const val of ['SCA', 'SECRET', 'API', 'MOBILE', 'CONTAINER', 'IAC', 'CLOUD']) {
      fireEvent.change(screen.getByDisplayValue(val === 'SCA' ? 'SAST' : val === 'SECRET' ? 'SCA' : val === 'API' ? 'SECRET' : val === 'MOBILE' ? 'API' : val === 'CONTAINER' ? 'MOBILE' : val === 'IAC' ? 'CONTAINER' : 'IAC'), { target: { value: val } })
      expect(screen.getByDisplayValue(val)).toBeInTheDocument()
    }
  })

  it('changes profile to all values', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByDisplayValue('STANDARD')).toBeInTheDocument())
    for (const val of ['PASSIVE', 'QUICK', 'DEEP', 'RELEASE_GATE', 'CONTINUOUS']) {
      const prev = val === 'PASSIVE' ? 'STANDARD' : val === 'QUICK' ? 'PASSIVE' : val === 'DEEP' ? 'QUICK' : val === 'RELEASE_GATE' ? 'DEEP' : 'RELEASE_GATE'
      fireEvent.change(screen.getByDisplayValue(prev), { target: { value: val } })
      expect(screen.getByDisplayValue(val)).toBeInTheDocument()
    }
  })

  it('fills target input', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByText('Scan Center')).toBeInTheDocument())
    const targetInput = screen.getByPlaceholderText(/Target/)
    fireEvent.change(targetInput, { target: { value: 'https://example.com' } })
    expect(targetInput).toHaveValue('https://example.com')
  })

  it('clicks Run Assessment and calls api.post', async () => {
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByText('Scan Center')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('option', { name: 'Test Project' })).toBeInTheDocument())
    fireEvent.click(screen.getByText('Run Assessment'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/scans', expect.objectContaining({ scannerType: 'SAST', profile: 'STANDARD' })))
  })

  it('displays scan table and data', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('Scan')).toBeInTheDocument()
      expect(screen.getByText('COMPLETED')).toBeInTheDocument()
      expect(screen.getByText('12')).toBeInTheDocument()
      expect(screen.getByText('30.0s')).toBeInTheDocument()
    })
  })

  it('shows empty state when no scans', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByText(/No scans yet/)).toBeInTheDocument())
  })

  it('displays scan orchestrator diagram', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('Scan Orchestrator')).toBeInTheDocument()
      expect(screen.getByText(/Finding Normalizer/)).toBeInTheDocument()
    })
  })

  it('changes project selector', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('displays scan initiatedBy', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('admin@vulnerax.io')).toBeInTheDocument()
    })
  })

  it('displays scan profile badge', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('STANDARD')).toBeInTheDocument()
    })
  })

  it('displays wizard heading', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText(/New Assessment Wizard/)).toBeInTheDocument()
    })
  })

  it('displays scope info', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText(/Scope requires Allowed targets/)).toBeInTheDocument()
    })
  })

  it('displays worker network policy info', async () => {
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText(/Workers have network policy/)).toBeInTheDocument()
    })
  })

  it('displays RUNNING scan status', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } })
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 's1', scannerType: 'DAST', target: 'https://example.com', profile: 'DEEP', status: 'RUNNING', findingsCount: 0, durationMs: null, createdAt: '2025-11-15T10:00:00Z', initiatedBy: 'admin@vulnerax.io' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('RUNNING')).toBeInTheDocument()
      expect(screen.getByText('-')).toBeInTheDocument()
    })
  })

  it('displays QUEUED scan status', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } })
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 's1', scannerType: 'SECRET', target: 'repo', profile: 'QUICK', status: 'QUEUED', findingsCount: null, createdAt: '2025-11-15T10:00:00Z', initiatedBy: 'user@vulnerax.io' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('SECRET')).toBeInTheDocument()
      expect(screen.getByText('QUEUED')).toBeInTheDocument()
    })
  })

  it('displays FAILED scan status', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } })
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 's1', scannerType: 'IAC', target: 'terraform/', profile: 'STANDARD', status: 'FAILED', findingsCount: 0, durationMs: 5000, createdAt: '2025-11-15T10:00:00Z', initiatedBy: 'ci@vulnerax.io' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Scans />))
    await waitFor(() => {
      expect(screen.getByText('FAILED')).toBeInTheDocument()
      expect(screen.getByText('5.0s')).toBeInTheDocument()
    })
  })

  it('alerts when no project available on run', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: {} } })
      if (url.includes('/scans')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<Scans />))
    await waitFor(() => expect(screen.getByText('Scan Center')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Run Assessment'))
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith('Create project first'))
    alertSpy.mockRestore()
  })
})
