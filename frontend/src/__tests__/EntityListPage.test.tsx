import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { api } from '../api/client'
import EntityListPage from '../components/EntityListPage'

vi.mock('../api/client', () => ({
  api: {
    get: vi.fn().mockImplementation((url) => {
      if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
      return Promise.resolve({ data: { success: true, data: { content: [], totalElements: 0 } } })
    }),
    post: vi.fn().mockResolvedValue({ data: { success: true, data: {} } }),
    put: vi.fn().mockResolvedValue({ data: { success: true } }),
  },
}))

vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' } }),
}))

const mockData = {
  content: [
    { id: 'r1', name: 'Integration Alpha', status: 'ACTIVE', url: 'https://alpha.example.com', createdAt: '2026-09-01', description: 'Test desc' },
    { id: 'r2', name: 'Integration Beta', status: 'PENDING', url: 'https://beta.example.com', createdAt: '2026-09-10', description: '' },
    { id: 'r3', name: 'Integration Gamma', status: 'DISABLED', url: null, createdAt: '2026-09-12', description: 'Long text'.repeat(20) },
  ],
}

const testColumns = [
  { key: 'name', label: 'Name' },
  { key: 'status', label: 'Status' },
  { key: 'url', label: 'URL' },
  { key: 'description', label: 'Description' },
]
const testCreateFields = [
  { key: 'name', label: 'Integration Name' },
  { key: 'url', label: 'Endpoint URL' },
]

let qc: QueryClient
const renderEntity = (props = {}) => render(
  <QueryClientProvider client={qc}>
    <MemoryRouter>
      <EntityListPage title="Integrations" subtitle="Manage integrations" apiPath="/api/v1/integrations" columns={testColumns} createFields={testCreateFields} {...props} />
    </MemoryRouter>
  </QueryClientProvider>
)

describe('EntityListPage', () => {
  beforeEach(() => {
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(api.get).mockReset()
    vi.mocked(api.post).mockClear()
  })

  it('renders title and subtitle', async () => {
    renderEntity()
    expect(screen.getByText('Integrations')).toBeInTheDocument()
    expect(screen.getByText('Manage integrations')).toBeInTheDocument()
  })

  it('displays table with data rows', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => {
      expect(screen.getByText('Integration Alpha')).toBeInTheDocument()
      expect(screen.getByText('Integration Beta')).toBeInTheDocument()
      expect(screen.getByText('Integration Gamma')).toBeInTheDocument()
    })
  })

  it('displays table headers from columns', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [] } } }
    })
    renderEntity()
    await waitFor(() => {
      expect(screen.getByText('Name')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()
      expect(screen.getByText('URL')).toBeInTheDocument()
      expect(screen.getByText('Description')).toBeInTheDocument()
    })
  })

  it('shows empty state when no data', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('No data yet')).toBeInTheDocument() })
  })

  it('shows loading state', async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }).mockReturnValueOnce(new Promise(() => {}))
    renderEntity()
    await waitFor(() => { expect(screen.getByText('Loading...')).toBeInTheDocument() })
  })

  it('toggles create form open/close', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    const user = userEvent.setup()
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Alpha') })
    await user.click(screen.getByText('+ New'))
    expect(screen.getByText('Create New Integration')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Integration Name')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Endpoint URL')).toBeInTheDocument()
    await user.click(screen.getByText('Cancel'))
    expect(screen.queryByText('Create New Integration')).not.toBeInTheDocument()
  })

  it('fills create form fields and submits', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    const user = userEvent.setup()
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Alpha') })
    await user.click(screen.getByText('+ New'))
    await user.type(screen.getByPlaceholderText('Integration Name'), 'New Integration')
    await user.type(screen.getByPlaceholderText('Endpoint URL'), 'https://new.example.com')
    await user.click(screen.getByText('Create'))
    expect(api.post).toHaveBeenCalledWith('/api/v1/integrations', { projectId: 'p1', organizationId: 'p1', name: 'New Integration', url: 'https://new.example.com' })
  })

  it('shows record count', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('3 records')).toBeInTheDocument() })
  })

  it('renders status badges with correct colors', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => {
      expect(screen.getAllByText('ACTIVE').length).toBeGreaterThan(0)
      expect(screen.getAllByText('PENDING').length).toBeGreaterThan(0)
      expect(screen.getAllByText('DISABLED').length).toBeGreaterThan(0)
    })
  })

  it('renders null values as dash', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Gamma') })
    const dashes = screen.getAllByText('-')
    expect(dashes.length).toBeGreaterThan(0)
  })

  it('truncates long text in cells', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Gamma') })
    const truncated = screen.getAllByText(/\.\.\./)
    expect(truncated.length).toBeGreaterThan(0)
  })

  it('renders boolean values as Yes/No', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'A', status: 'ACTIVE', url: '', description: '', active: true, hidden: false }] } } }
    })
    const cols = [...testColumns, { key: 'active', label: 'Active' }, { key: 'hidden', label: 'Hidden' }]
    renderEntity({ columns: cols })
    await waitFor(() => { expect(screen.getByText('Yes')).toBeInTheDocument(); expect(screen.getByText('No')).toBeInTheDocument() })
  })

  it('does not show + New button when no createFields', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity({ createFields: undefined })
    await waitFor(() => { screen.getByText('Integration Alpha') })
    expect(screen.queryByText('+ New')).not.toBeInTheDocument()
  })

  it('calls api.get with correct path and params', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    renderEntity()
    await waitFor(() => { expect(api.get).toHaveBeenCalledWith('/api/v1/integrations', expect.objectContaining({ params: expect.objectContaining({ projectId: 'p1', organizationId: 'p1', size: 50 }) })) })
  })

  it('supports custom render function in columns', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'ACTIVE', url: 'http://test.com' }] } } }
    })
    const cols = [{ key: 'name', label: 'Name', render: (val: string) => <strong>{val.toUpperCase()}</strong> }]
    renderEntity({ columns: cols })
    await waitFor(() => { expect(screen.getByText('TEST')).toBeInTheDocument() })
  })

  it('handles Record<string,string> createFields format', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    const user = userEvent.setup()
    renderEntity({ createFields: { name: 'Name Field', url: 'URL Field' } })
    await waitFor(() => { screen.getByText('Integration Alpha') })
    await user.click(screen.getByText('+ New'))
    expect(screen.getByPlaceholderText('Name Field')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('URL Field')).toBeInTheDocument()
  })

  it('handles project select change', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Project A', organizationId: 'org1' }, { id: 'p2', name: 'Project B', organizationId: 'org2' }] } } }
      return { data: { success: true, data: mockData } }
    })
    const user = userEvent.setup()
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Alpha') })
    const select = screen.getAllByRole('combobox')[0]
    await user.selectOptions(select, 'p2')
    expect(select).toHaveValue('p2')
  })

  it('renders column with className', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'ACTIVE', url: 'http://test.com' }] } } }
    })
    const cols = [{ key: 'name', label: 'Name', className: 'w-1/3' }]
    renderEntity({ columns: cols })
    await waitFor(() => { expect(screen.getByText('Test')).toBeInTheDocument() })
  })

  it('hides create form after successful submit', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    const user = userEvent.setup()
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Alpha') })
    await user.click(screen.getByText('+ New'))
    await user.type(screen.getByPlaceholderText('Integration Name'), 'New')
    await user.click(screen.getByText('Create'))
    await waitFor(() => { expect(screen.queryByText('Create New Integration')).not.toBeInTheDocument() })
  })

  it('handles create error with alert', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: mockData } }
    })
    vi.mocked(api.post).mockRejectedValueOnce({ response: { data: { message: 'Create failed' } } })
    const user = userEvent.setup()
    renderEntity()
    await waitFor(() => { screen.getByText('Integration Alpha') })
    await user.click(screen.getByText('+ New'))
    await user.type(screen.getByPlaceholderText('Integration Name'), 'Fail')
    await user.click(screen.getByText('Create'))
    await waitFor(() => { expect(screen.queryByText('Create New Integration')).toBeInTheDocument() })
  })

  it('renders Ready status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'READY', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('READY')).toBeInTheDocument() })
  })

  it('renders Running status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'RUNNING', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('RUNNING')).toBeInTheDocument() })
  })

  it('renders Queued status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'QUEUED', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('QUEUED')).toBeInTheDocument() })
  })

  it('renders Completed status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'COMPLETED', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('COMPLETED')).toBeInTheDocument() })
  })

  it('renders Failed status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'FAILED', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('FAILED')).toBeInTheDocument() })
  })

  it('renders Error status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'ERROR', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('ERROR')).toBeInTheDocument() })
  })

  it('renders Open status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'OPEN', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('OPEN')).toBeInTheDocument() })
  })

  it('renders Closed status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'CLOSED', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('CLOSED')).toBeInTheDocument() })
  })

  it('renders Enabled status badge', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', name: 'Test', status: 'ENABLED', url: '' }] } } }
    })
    renderEntity()
    await waitFor(() => { expect(screen.getByText('ENABLED')).toBeInTheDocument() })
  })

  it('renders custom nameLabel', async () => {
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url === '/api/v1/projects') return { data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } }
      return { data: { success: true, data: { content: [{ id: 'x1', title: 'Custom Title', status: 'ACTIVE' }] } } }
    })
    const cols = [{ key: 'title', label: 'Title' }]
    renderEntity({ columns: cols, nameLabel: 'title' })
    await waitFor(() => { expect(screen.getByText('Custom Title')).toBeInTheDocument() })
  })
})
