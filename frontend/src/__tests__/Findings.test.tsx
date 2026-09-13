import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import Findings from '../pages/Findings'
import { BrowserRouter } from 'react-router-dom'

// Mock the auth store
vi.mock('../store/auth', () => ({
  useAuth: () => ({
    token: 'mock-token',
    user: { email: 'test@vulnerax.com', role: 'DEVELOPER' },
  }),
}))

// Mock axios
vi.mock('axios', () => ({
  default: {
    get: vi.fn().mockResolvedValue({
      data: {
        success: true,
        data: {
          content: [
            {
              id: '1',
              findingId: 'FND-1001',
              title: 'SQL Injection in Login',
              severity: 'CRITICAL',
              status: 'OPEN',
              type: 'SAST',
              cwe: 'CWE-89',
              cvss: 9.8,
              assetName: 'auth-service',
            },
            {
              id: '2',
              findingId: 'FND-1002',
              title: 'XSS in Search',
              severity: 'HIGH',
              status: 'OPEN',
              type: 'DAST',
              cwe: 'CWE-79',
              cvss: 7.5,
              assetName: 'web-app',
            },
          ],
          totalElements: 2,
          totalPages: 1,
        },
      },
    }),
  },
}))

const renderWithRouter = (component) => {
  return render(<BrowserRouter>{component}</BrowserRouter>)
}

describe('Findings Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders findings list', async () => {
    renderWithRouter(<Findings />)

    await waitFor(() => {
      expect(screen.getByText(/findings/i)).toBeInTheDocument()
    })
  })

  it('displays finding entries', async () => {
    renderWithRouter(<Findings />)

    await waitFor(() => {
      expect(screen.getByText('SQL Injection in Login')).toBeInTheDocument()
      expect(screen.getByText('XSS in Search')).toBeInTheDocument()
    })
  })

  it('shows severity badges', async () => {
    renderWithRouter(<Findings />)

    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      expect(screen.getByText('HIGH')).toBeInTheDocument()
    })
  })

  it('displays finding IDs', async () => {
    renderWithRouter(<Findings />)

    await waitFor(() => {
      expect(screen.getByText('FND-1001')).toBeInTheDocument()
      expect(screen.getByText('FND-1002')).toBeInTheDocument()
    })
  })
})
