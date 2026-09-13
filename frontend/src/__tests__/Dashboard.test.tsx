import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import Dashboard from '../pages/Dashboard'
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
          securityScore: 75,
          totalFindings: 150,
          criticalFindings: 5,
          highFindings: 20,
          coverage: { sast: 80, dast: 60, sca: 90 },
          trend: [
            { month: 'Jan', findings: 100 },
            { month: 'Feb', findings: 120 },
            { month: 'Mar', findings: 150 },
          ],
        },
      },
    }),
  },
}))

const renderWithRouter = (component: React.ReactNode) => {
  return render(<BrowserRouter>{component}</BrowserRouter>)
}

describe('Dashboard Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders dashboard title', async () => {
    renderWithRouter(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText(/dashboard/i)).toBeInTheDocument()
    })
  })

  it('displays security score', async () => {
    renderWithRouter(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText(/75/)).toBeInTheDocument()
    })
  })

  it('displays findings count', async () => {
    renderWithRouter(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText(/150/)).toBeInTheDocument()
    })
  })
})
