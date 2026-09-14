import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/reports/export')) return Promise.resolve({ data: { success: true, data: { title: 'Test Report', content: 'report content' } } })
    if (url.includes('/reports')) return Promise.resolve({ data: { success: true, data: [{ id: 'r1', title: 'Executive Report', type: 'EXECUTIVE', format: 'PDF', classification: 'CONFIDENTIAL', status: 'GENERATED', createdAt: '2025-11-15T10:00:00Z' }] } })
    return Promise.resolve({ data: { success: true, data: [] } })
  }),
  mockPost: vi.fn().mockResolvedValue({ data: { success: true } }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Reports from '../pages/Reports'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Reports', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders title and subtitle', async () => {
    render(wrap(<Reports />))
    await waitFor(() => {
      expect(screen.getByText('Reporting Engine')).toBeInTheDocument()
      expect(screen.getByText(/Executive.*Technical.*Developer/)).toBeInTheDocument()
    })
  })

  it('displays project selector', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument())
  })

  it('changes report type to all values', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByDisplayValue('EXECUTIVE')).toBeInTheDocument())
    for (const val of ['TECHNICAL', 'DEVELOPER', 'PENTEST', 'RETEST', 'COMPLIANCE', 'SUPPLY_CHAIN', 'POSTURE', 'ATTACK_SURFACE']) {
      const prev = val === 'TECHNICAL' ? 'EXECUTIVE' : val === 'DEVELOPER' ? 'TECHNICAL' : val === 'PENTEST' ? 'DEVELOPER' : val === 'RETEST' ? 'PENTEST' : val === 'COMPLIANCE' ? 'RETEST' : val === 'SUPPLY_CHAIN' ? 'COMPLIANCE' : val === 'POSTURE' ? 'SUPPLY_CHAIN' : 'POSTURE'
      fireEvent.change(screen.getByDisplayValue(prev), { target: { value: val } })
      expect(screen.getByDisplayValue(val)).toBeInTheDocument()
    }
  })

  it('changes format to all values', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByDisplayValue('PDF')).toBeInTheDocument())
    for (const val of ['HTML', 'JSON', 'CSV', 'SARIF']) {
      const prev = val === 'HTML' ? 'PDF' : val === 'JSON' ? 'HTML' : val === 'CSV' ? 'JSON' : 'CSV'
      fireEvent.change(screen.getByDisplayValue(prev), { target: { value: val } })
      expect(screen.getByDisplayValue(val)).toBeInTheDocument()
    }
  })

  it('clicks Generate and calls api.post', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByText('Generate Report')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Generate'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/reports/generate', expect.objectContaining({ type: 'EXECUTIVE', format: 'PDF' })))
  })

  it('displays report table data', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByRole('option', { name: 'Test Project' })).toBeInTheDocument())
    await waitFor(() => {
      expect(screen.getByText('Executive Report')).toBeInTheDocument()
      expect(screen.getAllByText('EXECUTIVE').length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText('PDF').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('CONFIDENTIAL')).toBeInTheDocument()
      expect(screen.getByText('GENERATED')).toBeInTheDocument()
    })
  })

  it('clicks Export and calls api.get for export', async () => {
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByText('Export')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Export'))
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/api/v1/reports/r1/export', expect.objectContaining({ params: { format: 'JSON' } })))
  })

  it('shows empty state when no reports', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/reports') && !url.includes('/export')) return Promise.resolve({ data: { success: true, data: [] } })
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      return Promise.resolve({ data: { success: true, data: [] } })
    })
    render(wrap(<Reports />))
    await waitFor(() => expect(screen.getByText(/No reports\. Generate/)).toBeInTheDocument())
  })

  it('displays sample report structures', async () => {
    render(wrap(<Reports />))
    await waitFor(() => {
      expect(screen.getByText('Executive Report (sample structure)')).toBeInTheDocument()
      expect(screen.getByText('Compliance (ASVS 5.0)')).toBeInTheDocument()
    })
  })
})
