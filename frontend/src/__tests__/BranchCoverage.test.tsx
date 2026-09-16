import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}))

vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER', fullName: 'Test User' }, login: vi.fn(), logout: vi.fn() }),
}))

import Dashboard from '../pages/Dashboard'
import OneClickTest from '../pages/OneClickTest'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => (
  <QueryClientProvider client={qc()}>
    <MemoryRouter>{c}</MemoryRouter>
  </QueryClientProvider>
)

describe('Branch Coverage - Dashboard.tsx lines 48, 62, 88', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders bar chart Cell with known severity colors', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5, HIGH: 10, MEDIUM: 15, LOW: 20, INFO: 2 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Findings by Severity')).toBeInTheDocument())
  })

  it('renders pie chart Cell with known severity colors', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5, HIGH: 10 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('Risk Distribution')).toBeInTheDocument())
  })

  it('renders topRiskAssets with items (line 88 truthy branch)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: [{ name: 'API Gateway', type: 'API', criticality: 'CRITICAL' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText('API Gateway')).toBeInTheDocument())
  })

  it('renders topRiskAssets empty state (line 88 falsy branch)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 }, topRiskAssets: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })

  it('renders topRiskAssets empty when topRiskAssets is undefined', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/dashboard/posture')) return Promise.resolve({ data: { success: true, data: { bySeverity: { CRITICAL: 5 } } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Dashboard />))
    await waitFor(() => expect(screen.getByText(/No critical assets/)).toBeInTheDocument())
  })
})

describe('Branch Coverage - OneClickTest.tsx lines 84, 139, 171-177', () => {
  beforeEach(() => { vi.clearAllMocks() })

  const defaultGetImpl = (url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }

  const defaultPostImpl = (url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { id: 'new-proj-1' } } })
    return Promise.resolve({ data: { success: true, data: { id: '1' } } })
  }

  beforeEach(() => {
    mockGet.mockImplementation(defaultGetImpl)
    mockPost.mockImplementation(defaultPostImpl)
  })

  const goToStep2 = async () => {
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByDisplayValue(/Pilih project existing/), { target: { value: 'p1' } })
    fireEvent.click(screen.getByText(/Lanjut.*Platform/))
    await waitFor(() => expect(screen.getByText(/Langkah 2/)).toBeInTheDocument())
  }

  it('renders targets for each platform (line 139)', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/WEB — Target/)).toBeInTheDocument())
    expect(screen.getByPlaceholderText(/https:\/\/dsrv/)).toBeInTheDocument()
  })

  it('renders progress with queue info (line 177)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 3, target: 'https://example.com', detectedType: 'WEB', message: 'Done', queue: '1/2' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getAllByText(/Selesai/).length).toBeGreaterThan(0)
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('renders progress with currentAction (line 175)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'RUNNING', progress: 50, findingsCount: 0, target: 'https://example.com', detectedType: 'WEB', message: 'Scanning...', currentAction: 'Running SAST scanner...' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getByText(/Running SAST scanner/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('renders progress with no currentAction or message (line 175 fallback)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'RUNNING', progress: 50, findingsCount: 0, target: 'https://example.com', detectedType: 'WEB' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getByText(/Menyiapkan scanner/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('renders step 3 with status badge showing COMPLETED (line 171)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 3, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getAllByText(/COMPLETED/).length).toBeGreaterThan(0)
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('renders step 3 with status badge showing RUNNING (line 171)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'RUNNING', progress: 50, findingsCount: 0, target: 'https://example.com', detectedType: 'WEB', message: 'Scanning...' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getByText(/RUNNING/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)
})
