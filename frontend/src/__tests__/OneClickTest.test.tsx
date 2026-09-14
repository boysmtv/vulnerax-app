import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
    if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
    if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 5, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
    return Promise.resolve({ data: { success: true, data: { content: [] } } })
  }),
  mockPost: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { id: 'new-proj-1' } } })
    if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
    return Promise.resolve({ data: { success: true, data: { id: '1' } } })
  }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import OneClickTest from '../pages/OneClickTest'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('OneClickTest', () => {
  beforeEach(() => { vi.clearAllMocks() })

  const goToStep2 = async () => {
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByDisplayValue(/Pilih project existing/), { target: { value: 'p1' } })
    fireEvent.click(screen.getByText(/Lanjut.*Platform/))
    await waitFor(() => expect(screen.getByText(/Langkah 2/)).toBeInTheDocument())
  }

  it('renders step 1 and main heading', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      expect(screen.getByText(/Langkah 1/)).toBeInTheDocument()
      expect(screen.getByText(/Test Platform Apa Saja.*1 Klik/)).toBeInTheDocument()
    })
  })

  it('displays step indicators', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      expect(screen.getByText(/1\. Project/)).toBeInTheDocument()
      expect(screen.getByText(/2\. Platform & Target/)).toBeInTheDocument()
      expect(screen.getByText(/3\. Run & Report/)).toBeInTheDocument()
    })
  })

  it('displays project select and new project input', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      expect(screen.getByDisplayValue(/Pilih project existing/)).toBeInTheDocument()
      expect(screen.getByPlaceholderText(/Nama project baru/)).toBeInTheDocument()
    })
  })

  it('enables next button when project selected', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByDisplayValue(/Pilih project existing/), { target: { value: 'p1' } })
    expect(screen.getByText(/Lanjut.*Platform/)).not.toBeDisabled()
  })

  it('enables next button when new project name entered', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'New App' } })
    expect(screen.getByText(/Lanjut.*Platform/)).not.toBeDisabled()
  })

  it('navigates to step 2 on next click', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText('WEB')).toBeInTheDocument()
    expect(screen.getByText('API')).toBeInTheDocument()
  })

  it('toggles platform checkbox', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const webCheckbox = screen.getByText('WEB').closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement
    expect(webCheckbox.checked).toBe(true)
    fireEvent.click(webCheckbox)
    expect(webCheckbox.checked).toBe(false)
  })

  it('fills WEB target input', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/WEB — Target/)).toBeInTheDocument())
    const targetInput = screen.getByPlaceholderText(/https:\/\/dsrv/)
    fireEvent.change(targetInput, { target: { value: 'https://example.com' } })
    expect(targetInput).toHaveValue('https://example.com')
  })

  it('adds and removes target inputs', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/WEB — Target/)).toBeInTheDocument())
    fireEvent.click(screen.getByText(/\+ Tambah WEB target/))
    expect(screen.getAllByPlaceholderText(/https:\/\/dsrv/).length).toBe(2)
    const removeButtons = screen.getAllByText('×')
    fireEvent.click(removeButtons[1])
    expect(screen.getAllByPlaceholderText(/https:\/\/dsrv/).length).toBe(1)
  })

  it('navigates back to step 1', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.click(screen.getByText(/Kembali/))
    await waitFor(() => expect(screen.getByText(/Langkah 1/)).toBeInTheDocument())
  })

  it('displays auto-detect info', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/Sistem auto-detect/)).toBeInTheDocument())
  })

  it('displays all 6 platform options in step 2', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText('WEB')).toBeInTheDocument()
    expect(screen.getByText('API')).toBeInTheDocument()
    expect(screen.getByText('MOBILE')).toBeInTheDocument()
    expect(screen.getByText('REPO')).toBeInTheDocument()
    expect(screen.getByText('CONTAINER')).toBeInTheDocument()
    expect(screen.getByText('NETWORK')).toBeInTheDocument()
  })

  it('shows target placeholders for each platform type', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText('WEB')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/https:\/\/dsrv/)).toBeInTheDocument()
    const apiCheckbox = screen.getByText('API').closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(apiCheckbox)
    expect(screen.getByPlaceholderText(/https:\/\/api\.acme/)).toBeInTheDocument()
  })

  it('fills API target input', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const apiCheckbox = screen.getByText('API').closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(apiCheckbox)
    const apiInput = screen.getByPlaceholderText(/https:\/\/api\.acme/)
    fireEvent.change(apiInput, { target: { value: 'https://api.example.com/v1' } })
    expect(apiInput).toHaveValue('https://api.example.com/v1')
  })

  it('fills REPO target input', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const repoCheckbox = screen.getByText('REPO').closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(repoCheckbox)
    const repoInput = screen.getByPlaceholderText(/github\.com/)
    fireEvent.change(repoInput, { target: { value: 'github.com/acme/app' } })
    expect(repoInput).toHaveValue('github.com/acme/app')
  })

  it('starts test with existing project and progresses to step 3', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    const webInput = screen.getByPlaceholderText(/https:\/\/dsrv/)
    fireEvent.change(webInput, { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('alerts when no targets filled', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByDisplayValue(''), { target: { value: '' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => expect(alertSpy).toHaveBeenCalled())
    alertSpy.mockRestore()
  })

  it('shows all platform checkboxes', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText('WEB')).toBeInTheDocument()
    expect(screen.getByText('CONTAINER')).toBeInTheDocument()
    expect(screen.getByText('NETWORK')).toBeInTheDocument()
  })

  it('shows completion banner after test run finishes', async () => {
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
    const webInput = screen.getByPlaceholderText(/https:\/\/dsrv/)
    fireEvent.change(webInput, { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('shows run status for each target in step 3', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 5, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    const webInput = screen.getByPlaceholderText(/https:\/\/dsrv/)
    fireEvent.change(webInput, { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)
})
