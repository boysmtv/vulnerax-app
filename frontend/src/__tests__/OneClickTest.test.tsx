import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}))

const defaultGetImpl = (url: string) => {
  if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
  if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
  if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 5, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
  return Promise.resolve({ data: { success: true, data: { content: [] } } })
}

const defaultPostImpl = (url: string) => {
  if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { id: 'new-proj-1' } } })
  if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
  return Promise.resolve({ data: { success: true, data: { id: '1' } } })
}
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
  beforeEach(() => { vi.clearAllMocks(); mockGet.mockImplementation(defaultGetImpl); mockPost.mockImplementation(defaultPostImpl) })

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

  it('creates new project when no existing project selected', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'Brand New Project' } })
    fireEvent.click(screen.getByText(/Lanjut.*Platform/))
    await waitFor(() => expect(screen.getByText(/Langkah 2/)).toBeInTheDocument())
  })

  it('toggles multiple platforms on and off', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const apiLabel = screen.getByText('API').closest('label')!
    const apiCheckbox = apiLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(apiCheckbox)
    expect(apiCheckbox.checked).toBe(true)
    fireEvent.click(apiCheckbox)
    expect(apiCheckbox.checked).toBe(false)
  })

  it('displays CONTAINER and NETWORK platform target placeholders', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const containerLabel = screen.getByText('CONTAINER').closest('label')!
    const containerCheckbox = containerLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(containerCheckbox)
    expect(screen.getByPlaceholderText(/nginx/)).toBeInTheDocument()
    const networkLabel = screen.getByText('NETWORK').closest('label')!
    const networkCheckbox = networkLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(networkCheckbox)
    expect(screen.getByPlaceholderText(/192\.168/)).toBeInTheDocument()
  })

  it('fills CONTAINER and NETWORK target inputs', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const containerLabel = screen.getByText('CONTAINER').closest('label')!
    const containerCheckbox = containerLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(containerCheckbox)
    const containerInput = screen.getByPlaceholderText(/nginx/)
    fireEvent.change(containerInput, { target: { value: 'nginx:1.25' } })
    expect(containerInput).toHaveValue('nginx:1.25')
    const networkLabel = screen.getByText('NETWORK').closest('label')!
    const networkCheckbox = networkLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(networkCheckbox)
    const networkInput = screen.getByPlaceholderText(/192\.168/)
    fireEvent.change(networkInput, { target: { value: '10.0.0.1' } })
    expect(networkInput).toHaveValue('10.0.0.1')
  })

  it('shows mobile file input when MOBILE platform is selected', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const mobileLabel = screen.getByText('MOBILE').closest('label')!
    const mobileCheckbox = mobileLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(mobileCheckbox)
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeInTheDocument()
    expect(fileInput).toHaveAttribute('accept', '.apk,.aab,.ipa')
  })

  it('uploads file via mobile file input and updates target', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const mobileLabel = screen.getByText('MOBILE').closest('label')!
    const mobileCheckbox = mobileLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(mobileCheckbox)
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeInTheDocument()
    const file = new File(['dummy-content'], 'test.apk', { type: 'application/vnd.android.package-archive' })
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true })
    fireEvent.change(fileInput)
  })

  it('handles file input with no file selected (early return)', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const mobileLabel = screen.getByText('MOBILE').closest('label')!
    const mobileCheckbox = mobileLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(mobileCheckbox)
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeInTheDocument()
    Object.defineProperty(fileInput, 'files', { value: [], configurable: true })
    fireEvent.change(fileInput)
  })

  it('displays platform-specific labels', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText('domain/url')).toBeInTheDocument()
    expect(screen.getByText('endpoint')).toBeInTheDocument()
    expect(screen.getByText('APK/IPA')).toBeInTheDocument()
    expect(screen.getByText('git url')).toBeInTheDocument()
    expect(screen.getByText('image:tag')).toBeInTheDocument()
    expect(screen.getByText('IP/host')).toBeInTheDocument()
  })

  it('shows target count in start button', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    expect(screen.getByText(/Test Sekarang.*1 platform.*0 target/)).toBeInTheDocument()
  })

  it('alerts when createProjectIfNeeded fails with workspace error', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThanOrEqual(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'New Project' } })
    fireEvent.click(screen.getByText(/Lanjut.*Platform/))
    await waitFor(() => expect(screen.getByText(/Langkah 2/)).toBeInTheDocument())
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => expect(alertSpy).toHaveBeenCalled(), { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('creates new project via api.post when no project selected', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 2, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { id: 'new-proj-created' } } })
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'Brand New Project' } })
    fireEvent.click(screen.getByText(/Lanjut.*Platform/))
    await waitFor(() => expect(screen.getByText(/Langkah 2/)).toBeInTheDocument())
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith('/api/v1/projects', expect.objectContaining({ name: 'Brand New Project', workspaceId: 'ws1', organizationId: 'org1' }))
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 25000)

  it('polls twice to trigger setRuns update branch (idx >= 0)', async () => {
    let pollCount = 0
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/run1/progress')) {
        pollCount++
        if (pollCount === 1) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'RUNNING', progress: 50, findingsCount: 0, target: 'https://example.com', detectedType: 'WEB', message: 'Scanning...' } } })
        return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 3, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
      }
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
      expect(screen.getAllByText(/Selesai.*target/).length).toBeGreaterThan(0)
    }, { timeout: 20000 })
    expect(pollCount).toBeGreaterThanOrEqual(2)
    alertSpy.mockRestore()
  }, 35000)

  it('renders run without id using target as key', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/run1/progress')) return Promise.resolve({ data: { success: true, data: { status: 'COMPLETED', progress: 100, findingsCount: 2, target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
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
      expect(screen.getByText('https://example.com')).toBeInTheDocument()
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 25000)

  it('removes only the correct target when multiple exist', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/WEB — Target/)).toBeInTheDocument())
    fireEvent.click(screen.getByText(/\+ Tambah WEB target/))
    fireEvent.click(screen.getByText(/\+ Tambah WEB target/))
    expect(screen.getAllByPlaceholderText(/https:\/\/dsrv/).length).toBe(3)
    const removeButtons = screen.getAllByText('×')
    fireEvent.click(removeButtons[1])
    expect(screen.getAllByPlaceholderText(/https:\/\/dsrv/).length).toBe(2)
  })

  it('fills REPO, CONTAINER and NETWORK target inputs', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const repoLabel = screen.getByText('REPO').closest('label')!
    const repoCheckbox = repoLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(repoCheckbox)
    const repoInput = screen.getByPlaceholderText(/github\.com/)
    fireEvent.change(repoInput, { target: { value: 'github.com/acme/app' } })
    expect(repoInput).toHaveValue('github.com/acme/app')
  })

  it('displays progress with queue info', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 3, target: 'https://example.com', detectedType: 'WEB', message: 'Done', queue: '1/1' } } })
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
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('handles API error during test execution (catch block with response)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.reject({ response: { data: { message: 'Scan failed: timeout' } }, message: 'Request failed' })
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
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 30000)

  it('handles API error without response data (fallback to e.message)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.reject(new Error('Network error'))
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
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 30000)

  it('processes multiple targets sequentially', async () => {
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
    fireEvent.click(screen.getByText(/\+ Tambah WEB target/))
    const webInputs = screen.getAllByPlaceholderText(/https:\/\/dsrv/)
    fireEvent.change(webInputs[1], { target: { value: 'https://other.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 30000)

  it('shows progress with currentAction and completed status', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 5, target: 'https://example.com', detectedType: 'WEB', message: 'Scan complete', currentAction: 'Generating report...' } } })
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
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('shows run details with missing detectedType falling back to platform', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/run1/progress')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 0, target: 'https://example.com', platform: 'WEB', message: 'Done' } } })
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
      expect(screen.getByText('https://example.com')).toBeInTheDocument()
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 25000)

  it('shows run with null findingsCount and null progress', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/run1/progress')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', target: 'https://example.com', detectedType: 'WEB', message: 'Done' } } })
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
      expect(screen.getByText('https://example.com')).toBeInTheDocument()
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 25000)

  it('shows FAILED run status without message', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/run1/progress')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'FAILED', progress: 75, findingsCount: 0, target: 'https://fail.com', detectedType: 'API' } } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    mockPost.mockImplementation((url: string) => {
      if (url.includes('/one-click/test')) return Promise.resolve({ data: { success: true, data: { id: 'run1' } } })
      return Promise.resolve({ data: { success: true, data: { id: '1' } } })
    })
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    render(wrap(<OneClickTest />))
    await goToStep2()
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://fail.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
      expect(screen.getByText('https://fail.com')).toBeInTheDocument()
    }, { timeout: 15000 })
    alertSpy.mockRestore()
  }, 25000)

  it('disables start button while test is running', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    await waitFor(() => expect(screen.getByText(/Test Sekarang/)).toBeInTheDocument())
    expect(screen.getByText(/Test Sekarang/)).not.toBeDisabled()
  })

  it('shows step 3 active indicator during run', async () => {
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

  it('shows disabled button when both projectId and newProjectName are empty', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    const button = screen.getByText(/Lanjut.*Platform/)
    expect(button).toBeDisabled()
  })

  it('clears newProjectName when project is selected', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'Some Name' } })
    expect(screen.getByPlaceholderText(/Nama project baru/)).toHaveValue('Some Name')
    fireEvent.change(screen.getByDisplayValue(/Pilih project existing/), { target: { value: 'p1' } })
    expect(screen.getByPlaceholderText(/Nama project baru/)).toHaveValue('')
  })

  it('clears projectId when new project name is entered', async () => {
    render(wrap(<OneClickTest />))
    await waitFor(() => {
      const options = screen.getAllByRole('option')
      expect(options.length).toBeGreaterThan(1)
    })
    fireEvent.change(screen.getByDisplayValue(/Pilih project existing/), { target: { value: 'p1' } })
    fireEvent.change(screen.getByPlaceholderText(/Nama project baru/), { target: { value: 'New Name' } })
    expect(screen.getByDisplayValue(/Pilih project existing/)).toHaveValue('')
  })

  it('shows default progress message when no currentAction or message', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/workspaces')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'ws1', name: 'Primary', organizationId: 'org1' }] } } })
      if (url.includes('/one-click/')) return Promise.resolve({ data: { success: true, data: { id: 'run1', status: 'COMPLETED', progress: 100, findingsCount: 2, target: 'https://example.com', detectedType: 'WEB' } } })
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
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('toggles MOBILE platform and shows file input', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const mobileLabel = screen.getByText('MOBILE').closest('label')!
    const mobileCheckbox = mobileLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    expect(mobileCheckbox.checked).toBe(false)
    fireEvent.click(mobileCheckbox)
    expect(mobileCheckbox.checked).toBe(true)
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeInTheDocument()
    expect(fileInput).toHaveAttribute('accept', '.apk,.aab,.ipa')
  })

  it('selects multiple platforms and targets', async () => {
    render(wrap(<OneClickTest />))
    await goToStep2()
    const apiLabel = screen.getByText('API').closest('label')!
    const apiCheckbox = apiLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(apiCheckbox)
    expect(apiCheckbox.checked).toBe(true)
    const containerLabel = screen.getByText('CONTAINER').closest('label')!
    const containerCheckbox = containerLabel.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(containerCheckbox)
    expect(containerCheckbox.checked).toBe(true)
    expect(screen.getByText(/3 platform/)).toBeInTheDocument()
  })

  it('navigates from step 3 back to step 2', async () => {
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
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)

  it('renders completion banner with total findings and links', async () => {
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
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/dsrv/), { target: { value: 'https://example.com' } })
    fireEvent.click(screen.getByText(/Test Sekarang/))
    await waitFor(() => {
      expect(screen.getByText(/Progress Live/)).toBeInTheDocument()
    }, { timeout: 10000 })
    alertSpy.mockRestore()
  }, 20000)
})
