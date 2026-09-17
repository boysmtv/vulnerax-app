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
  beforeEach(() => {
    vi.clearAllMocks()
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
  })

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
    mockGet.mockImplementation((url: string) => {
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
    mockGet.mockImplementation((url: string) => {
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

  it('handles data as object with content property', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'c1', domain: 'SCA', status: 'TESTED', coveragePercent: 90, provider: 'GITHUB' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText(/SCA.*TESTED.*90/)).toBeInTheDocument()
    })
  })

  it('shows No data yet when JSON.stringify returns empty array', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument())
  })

  it('handles create error without response', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    mockPost.mockRejectedValueOnce(new Error('Network error'))
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => {
      expect(alertSpy).toHaveBeenCalledWith('Network error')
    })
    alertSpy.mockRestore()
  })

  it('displays loading state', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return new Promise(() => {})
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Test Project')).toBeInTheDocument())
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('handles null data from coverage API', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: null } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Test Project')).toBeInTheDocument()
      expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument()
    })
  })

  it('handles data as object with content property being null', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: { content: null } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Test Project')).toBeInTheDocument()
      expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument()
    })
  })

  it('displays coverage data as JSON array in pre element', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85 }, { id: 'c2', domain: 'DAST', status: 'TESTED', coveragePercent: 70 }, { id: 'c3', domain: 'SCA', status: 'TESTED', coveragePercent: 90 }, { id: 'c4', domain: 'SECRETS', status: 'PASSED', coveragePercent: 95 }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      const pre = document.querySelector('pre')
      expect(pre).toBeInTheDocument()
      expect(pre!.textContent).toContain('SAST')
    })
  })

  it('displays list items when data is array with items', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getAllByText(/SAST/).length).toBeGreaterThan(0)
      expect(screen.getAllByText(/TESTED/).length).toBeGreaterThan(0)
    })
  })

  it('hides empty state when list has items', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Test Project')).toBeInTheDocument()
    })
    expect(screen.queryByText(/No data.*Security Coverage will appear/)).not.toBeInTheDocument()
  })

  it('handles projects API error gracefully', async () => {
    mockGet.mockRejectedValueOnce(new Error('Network error'))
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Security Coverage')).toBeInTheDocument()
    })
  })

  it('handles coverage API error gracefully', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.reject(new Error('Coverage API down'))
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('Test Project')).toBeInTheDocument()
      expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument()
    })
  })

  it('displays non-TESTED status with different badge color', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [{ id: 'c1', domain: 'SAST', status: 'PENDING', coveragePercent: 50, provider: 'SONAR' }] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('PENDING')).toBeInTheDocument()
      expect(screen.getByText('50%')).toBeInTheDocument()
      expect(screen.getByText('Provider: SONAR')).toBeInTheDocument()
    })
  })

  it('handles CreateDemo success with content property response', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    mockPost.mockResolvedValueOnce({ data: { success: true } })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => expect(mockPost).toHaveBeenCalled())
  })

  it('handles CreateDemo success with null response data', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    mockPost.mockResolvedValueOnce({ data: { success: true } })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => expect(mockPost).toHaveBeenCalled())
  })

  it('handles CreateDemo refresh returning content object', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    let callCount = 0
    mockPost.mockImplementation(() => {
      callCount++
      return Promise.resolve({ data: { success: true } })
    })
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) {
        if (callCount > 0) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' }] } } })
        return Promise.resolve({ data: { success: true, data: [] } })
      }
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => expect(screen.getByText('SAST')).toBeInTheDocument())
  })

  it('handles CreateDemo refresh returning null data', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    let callCount = 0
    mockPost.mockImplementation(() => {
      callCount++
      return Promise.resolve({ data: { success: true } })
    })
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) {
        if (callCount > 0) return Promise.resolve({ data: { success: true, data: null } })
        return Promise.resolve({ data: { success: true, data: [] } })
      }
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => expect(screen.getByText('Create Demo')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Create Demo'))
    await waitFor(() => expect(screen.getByText(/No data.*Security Coverage will appear/)).toBeInTheDocument())
  })

  it('displays multiple coverage items with progress bars', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/coverage')) return Promise.resolve({ data: { success: true, data: [
        { id: 'c1', domain: 'SAST', status: 'TESTED', coveragePercent: 85, provider: 'AWS' },
        { id: 'c2', domain: 'DAST', status: 'TESTED', coveragePercent: 70, provider: 'BURP' },
        { id: 'c3', domain: 'SCA', status: 'PASSED', coveragePercent: 95, provider: 'SCATool' }
      ] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Coverage />))
    await waitFor(() => {
      expect(screen.getByText('SAST')).toBeInTheDocument()
      expect(screen.getByText('DAST')).toBeInTheDocument()
      expect(screen.getByText('SCA')).toBeInTheDocument()
      expect(screen.getByText('85%')).toBeInTheDocument()
      expect(screen.getByText('70%')).toBeInTheDocument()
      expect(screen.getByText('95%')).toBeInTheDocument()
    })
  })
})
