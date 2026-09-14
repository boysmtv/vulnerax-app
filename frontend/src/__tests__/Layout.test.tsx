import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../api/client', () => ({
  api: { get: vi.fn().mockResolvedValue({ data: { success: true, data: { content: [] } } }), post: vi.fn().mockResolvedValue({ data: { success: true } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER', fullName: 'Test User' }, login: vi.fn(), logout: vi.fn() }),
}))

import Layout from '../components/Layout'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrapWithLayout = (children: React.ReactNode, initialEntries: string[] = ['/dashboard']) => (
  <QueryClientProvider client={qc()}>
    <MemoryRouter initialEntries={initialEntries}>
      <Layout>{children}</Layout>
    </MemoryRouter>
  </QueryClientProvider>
)

const clickAdvanced = () => fireEvent.click(screen.getByRole('button', { name: /Advanced/ }))

describe('Layout', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders VulneraX branding in sidebar', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('VulneraX')).toBeInTheDocument()
    expect(screen.getByText('Security Platform')).toBeInTheDocument()
  })

  it('renders Dashboard nav link', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })

  it('renders Findings nav link', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Findings')).toBeInTheDocument()
  })

  it('renders Reports nav link', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Reports')).toBeInTheDocument()
  })

  it('renders primary nav items', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Test Sekarang (1 Klik)')).toBeInTheDocument()
  })

  it('renders Advanced button with count', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByRole('button', { name: /Advanced/ })).toBeInTheDocument()
  })

  it('expands advanced nav on click', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Projects')).toBeInTheDocument()
    expect(screen.getByText('Assets')).toBeInTheDocument()
    expect(screen.getByText('Scans')).toBeInTheDocument()
  })

  it('collapses advanced nav on second click', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Projects')).toBeInTheDocument()
    clickAdvanced()
    expect(screen.queryByText('Projects')).not.toBeInTheDocument()
  })

  it('shows mobile sidebar hint when collapsed', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText(/Klik Advanced untuk 20\+ tools/)).toBeInTheDocument()
  })

  it('displays user email in sidebar footer', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText(/test@vulnerax\.io/)).toBeInTheDocument()
  })

  it('displays user role in sidebar footer', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText(/DEVELOPER/)).toBeInTheDocument()
  })

  it('displays user fullName in sidebar footer', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Test User')).toBeInTheDocument()
  })

  it('renders Logout button', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText('Logout')).toBeInTheDocument()
  })

  it('renders children content', () => {
    render(wrapWithLayout(<div>Test Content</div>))
    expect(screen.getByText('Test Content')).toBeInTheDocument()
  })

  it('renders header bar', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText(/Single Source of Truth for Technical Security Risk/)).toBeInTheDocument()
  })

  it('renders SaaS badge in header', () => {
    render(wrapWithLayout(<div>Content</div>))
    expect(screen.getByText(/SaaS.*Hybrid.*On-Prem/)).toBeInTheDocument()
  })

  it('renders mobile menu button', () => {
    render(wrapWithLayout(<div>Content</div>))
    const menuButton = screen.getByRole('button', { name: '' })
    expect(menuButton).toBeInTheDocument()
  })

  it('toggles mobile sidebar on menu button click', () => {
    render(wrapWithLayout(<div>Content</div>))
    const menuButton = screen.getByRole('button', { name: '' })
    fireEvent.click(menuButton)
    expect(screen.getByText('VulneraX')).toBeInTheDocument()
  })

  it('highlights active nav link for dashboard', () => {
    render(wrapWithLayout(<div>Content</div>), ['/dashboard'])
    const dashboardLink = screen.getByText('Dashboard').closest('a')
    expect(dashboardLink?.className).toContain('bg-indigo-600')
  })

  it('renders advanced nav items including Mobile RE', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Mobile RE')).toBeInTheDocument()
  })

  it('renders advanced nav items including Attack Graph', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Attack Graph')).toBeInTheDocument()
  })

  it('renders advanced nav items including Threat Model', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Threat Model')).toBeInTheDocument()
  })

  it('renders advanced nav items including Compliance', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Compliance')).toBeInTheDocument()
  })

  it('renders advanced nav items including Notifications', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Notifications')).toBeInTheDocument()
  })

  it('renders advanced nav items including Coverage', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Coverage')).toBeInTheDocument()
  })

  it('renders advanced nav items including Supply Chain', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Supply Chain')).toBeInTheDocument()
  })

  it('renders advanced nav items including Pentest', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Pentest')).toBeInTheDocument()
  })

  it('renders advanced nav items including CI/CD', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('CI/CD')).toBeInTheDocument()
  })

  it('renders advanced nav items including IAM', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('IAM')).toBeInTheDocument()
  })

  it('renders advanced nav items including Containers', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Containers')).toBeInTheDocument()
  })

  it('renders advanced nav items including AI/LLM', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('AI/LLM')).toBeInTheDocument()
  })

  it('renders advanced nav items including Browser Ext', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Browser Ext')).toBeInTheDocument()
  })

  it('renders advanced nav items including Firmware', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Firmware')).toBeInTheDocument()
  })

  it('renders advanced nav items including Integrations', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Integrations')).toBeInTheDocument()
  })

  it('renders advanced nav items including Campaigns', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Campaigns')).toBeInTheDocument()
  })

  it('highlights active nav for advanced items', async () => {
    render(wrapWithLayout(<div>Content</div>), ['/assets'])
    clickAdvanced()
    const assetsLink = screen.getByText('Assets').closest('a')
    expect(assetsLink).toHaveAttribute('href', '/assets')
    expect(assetsLink?.className).toContain('rounded-lg')
  })

  it('renders Cloud advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Cloud')).toBeInTheDocument()
  })

  it('renders K8s advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('K8s')).toBeInTheDocument()
  })

  it('renders IaC advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('IaC')).toBeInTheDocument()
  })

  it('renders Network advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Network')).toBeInTheDocument()
  })

  it('renders Databases advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Databases')).toBeInTheDocument()
  })

  it('renders Policies advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Policies')).toBeInTheDocument()
  })

  it('renders Retest advanced nav item', () => {
    render(wrapWithLayout(<div>Content</div>))
    clickAdvanced()
    expect(screen.getByText('Retest')).toBeInTheDocument()
  })

  it('highlights active nav for findings', () => {
    render(wrapWithLayout(<div>Content</div>, ['/findings']))
    const findingsLink = screen.getByText('Findings').closest('a')!
    expect(findingsLink).toHaveAttribute('href', '/findings')
    expect(findingsLink.className).toMatch(/bg-indigo-600/)
  })

  it('highlights active nav for reports', () => {
    render(wrapWithLayout(<div>Content</div>, ['/reports']))
    const reportsLink = screen.getByText('Reports').closest('a')!
    expect(reportsLink).toHaveAttribute('href', '/reports')
    expect(reportsLink.className).toMatch(/bg-indigo-600/)
  })

  it('highlights active nav for primary test page', () => {
    render(wrapWithLayout(<div>Content</div>, ['/']))
    const testLink = screen.getByText('Test Sekarang (1 Klik)').closest('a')!
    expect(testLink).toHaveAttribute('href', '/')
    expect(testLink.className).toMatch(/bg-indigo-600/)
  })
})
