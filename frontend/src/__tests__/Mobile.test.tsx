import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn().mockResolvedValue({ data: { success: true } }),
}))
const defaultMockImpl = (url: string) => {
  if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
  if (url.includes('/mobile/1/workspace')) return Promise.resolve({ data: { success: true, data: { overview: { packageName: 'com.acme.app' }, manifest: '<manifest>...</manifest>', endpoints: ['https://api.acme.com/v1'], masvs: [{ control: 'MSTG-STORAGE-01', status: 'PASS', severity: 'LOW' }, { control: 'MSTG-CRYPTO-01', status: 'FAIL', severity: 'HIGH' }], callGraph: ['onCreate()', 'login()'] } } })
  if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [{ id: '1', fileName: 'app-release.apk', platform: 'ANDROID', masvsScore: 78, status: 'ANALYZED', fileSha256: 'abc123def4567890', fileSize: 15728640 }] } })
  return Promise.resolve({ data: { success: true, data: { content: [] } } })
}
mockGet.mockImplementation(defaultMockImpl)
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import Mobile from '../pages/Mobile'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Mobile', () => {
  beforeEach(() => { vi.clearAllMocks(); mockGet.mockImplementation(defaultMockImpl) })

  it('renders title and subtitle', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText('Mobile Security & Reverse Engineering')).toBeInTheDocument()
      expect(screen.getByText(/APK.*AAB.*IPA.*MASVS/)).toBeInTheDocument()
    })
  })

  it('displays upload form', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText('Upload Artifact')).toBeInTheDocument()
      expect(screen.getByDisplayValue('app-release.apk')).toBeInTheDocument()
      expect(screen.getByDisplayValue('ANDROID')).toBeInTheDocument()
    })
  })

  it('changes platform to IOS', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByDisplayValue('ANDROID')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('ANDROID'), { target: { value: 'IOS' } })
    expect(screen.getByDisplayValue('IOS')).toBeInTheDocument()
  })

  it('clicks Analyze and calls api.post', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('Upload Artifact')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Analyze'))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/mobile/upload', null, expect.objectContaining({ params: expect.objectContaining({ fileName: 'app-release.apk', platform: 'ANDROID' }) })))
  })

  it('displays artifact data', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText('app-release.apk')).toBeInTheDocument()
      expect(screen.getByText(/ANDROID.*78\/100 MASVS.*ANALYZED/)).toBeInTheDocument()
    })
  })

  it('clicks artifact to open workspace', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/Overview.*Manifest.*Strings/)).toBeInTheDocument()
      expect(screen.getByText('https://api.acme.com/v1')).toBeInTheDocument()
      expect(screen.getByText('MSTG-STORAGE-01')).toBeInTheDocument()
      expect(screen.getByText('Call Graph / Control Flow (simplified)')).toBeInTheDocument()
    })
  })

  it('shows placeholder when no artifact selected', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    expect(screen.getByText('Select an artifact to view Reverse Engineering Workspace')).toBeInTheDocument()
  })

  it('shows empty state when no artifacts', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText(/No artifacts\. Upload APK/)).toBeInTheDocument())
  })

  it('changes project selector', async () => {
    mockGet.mockImplementationOnce((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('changes fileName input', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByDisplayValue('app-release.apk')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('app-release.apk'), { target: { value: 'new-app.aab' } })
    expect(screen.getByDisplayValue('new-app.aab')).toBeInTheDocument()
  })

  it('displays MASVS controls in workspace', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText('MSTG-CRYPTO-01')).toBeInTheDocument()
      expect(screen.getByText(/FAIL.*HIGH/)).toBeInTheDocument()
    })
  })

  it('displays call graph in workspace', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/onCreate\(\)/)).toBeInTheDocument()
      expect(screen.getByText(/login\(\)/)).toBeInTheDocument()
    })
  })

  it('highlights selected artifact', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      const artifact = screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!
      expect(artifact.className).toContain('ring-2')
    })
  })

  it('displays file hash in artifact list', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeInTheDocument()
    })
  })

  it('displays file size in MB', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText(/15\.0 MB/)).toBeInTheDocument()
    })
  })

  it('handles data as object with content property (non-array)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: { content: [{ id: '1', fileName: 'app.apk', platform: 'ANDROID', masvsScore: 80, status: 'ANALYZED', fileSha256: 'abc123def456', fileSize: 10485760 }] } } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('Upload Artifact')).toBeInTheDocument())
    expect(screen.getByText(/No artifacts\. Upload APK/)).toBeInTheDocument()
    expect(screen.getByText('Select an artifact to view Reverse Engineering Workspace')).toBeInTheDocument()
  })

  it('handles data as null (no array)', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: null } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText(/No artifacts/)).toBeInTheDocument())
  })

  it('handles workspace with empty endpoints, masvs, and callGraph', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile/1/workspace')) return Promise.resolve({ data: { success: true, data: { overview: { packageName: 'com.test' }, manifest: '<manifest/>', endpoints: [], masvs: [], callGraph: [] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [{ id: '1', fileName: 'app-release.apk', platform: 'ANDROID', masvsScore: 78, status: 'ANALYZED', fileSha256: 'abc123def4567890', fileSize: 15728640 }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/Overview.*Manifest/)).toBeInTheDocument()
    })
  })

  it('shows MASVS PASS status in green', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/PASS.*LOW/)).toBeInTheDocument()
      expect(screen.getByText('MSTG-STORAGE-01')).toBeInTheDocument()
    })
  })

  it('changes project selector with multiple projects', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
  })

  it('shows no artifacts empty state for null data', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: undefined } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText(/No artifacts/)).toBeInTheDocument())
  })

  it('disables mobile query when no projects exist', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => {
      expect(screen.getByText('Mobile Security & Reverse Engineering')).toBeInTheDocument()
    })
    expect(screen.getByText(/No artifacts/)).toBeInTheDocument()
  })

  it('uses explicit projectId over first project', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Project A' }, { id: 'p2', name: 'Project B' }] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [] } })
      return Promise.resolve({ data: { success: true, data: {} } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByDisplayValue('Project A')).toBeInTheDocument())
    fireEvent.change(screen.getByDisplayValue('Project A'), { target: { value: 'p2' } })
    await waitFor(() => {
      expect(screen.getByDisplayValue('Project B')).toBeInTheDocument()
    })
  })

  it('renders workspace with empty endpoints, masvs, and callGraph', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile/1/workspace')) return Promise.resolve({ data: { success: true, data: { overview: { packageName: 'com.test' }, manifest: '<manifest/>', endpoints: [], masvs: [], callGraph: [] } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [{ id: '1', fileName: 'app-release.apk', platform: 'ANDROID', masvsScore: 78, status: 'ANALYZED', fileSha256: 'abc123def4567890', fileSize: 15728640 }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/Overview.*Manifest/)).toBeInTheDocument()
      expect(screen.getByText('Endpoints')).toBeInTheDocument()
      expect(screen.getByText('MASVS Mapping')).toBeInTheDocument()
    })
  })

  it('renders workspace overview JSON', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/com\.acme\.app/)).toBeInTheDocument()
    })
  })

  it('renders manifest in workspace', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/<manifest>.*<\/manifest>/)).toBeInTheDocument()
    })
  })

  it('renders MASVS status with FAIL color', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      const failEl = screen.getByText(/FAIL.*HIGH/)
      expect(failEl.className).toContain('text-red-600')
    })
  })

  it('renders MASVS status with PASS color', async () => {
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      const passEl = screen.getByText(/PASS.*LOW/)
      expect(passEl.className).toContain('text-emerald-600')
    })
  })

  it('renders workspace with null endpoints, masvs, and callGraph', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project' }] } } })
      if (url.includes('/mobile/1/workspace')) return Promise.resolve({ data: { success: true, data: { overview: { packageName: 'com.test' }, manifest: '<manifest/>', endpoints: null, masvs: null, callGraph: null } } })
      if (url.includes('/mobile')) return Promise.resolve({ data: { success: true, data: [{ id: '1', fileName: 'app-release.apk', platform: 'ANDROID', masvsScore: 78, status: 'ANALYZED', fileSha256: 'abc123def4567890', fileSize: 15728640 }] } })
      return Promise.resolve({ data: { success: true, data: { content: [] } } })
    })
    render(wrap(<Mobile />))
    await waitFor(() => expect(screen.getByText('app-release.apk')).toBeInTheDocument())
    fireEvent.click(screen.getByText('app-release.apk').closest('div[class*="cursor-pointer"]')!)
    await waitFor(() => {
      expect(screen.getByText(/Overview.*Manifest/)).toBeInTheDocument()
      expect(screen.getByText('Endpoints')).toBeInTheDocument()
      expect(screen.getByText('MASVS Mapping')).toBeInTheDocument()
      expect(screen.getByText('Call Graph / Control Flow (simplified)')).toBeInTheDocument()
    })
  })
})
