import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockGet } = vi.hoisted(() => ({
  mockGet: vi.fn().mockImplementation((url: string) => {
    if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
    return Promise.resolve({ data: { success: true, data: { content: [{ id: '1', name: 'Test Item', status: 'ACTIVE', createdAt: '2026-01-01', findingId: 'FND-001', type: 'SAST', provider: 'AWS', platform: 'GITHUB_ACTIONS', host: '10.0.0.1', port: '443', principalName: 'alice', principalType: 'User', version: '1.0', severity: 'HIGH', scope: 'Target', comment: 'Retest reason', result: 'PASS', fileName: 'firmware.bin', filePath: 'main.tf', repository: 'acme/app' }], totalElements: 1 } } })
  }),
}))
vi.mock('../api/client', () => ({
  api: { get: mockGet, post: vi.fn().mockResolvedValue({ data: { success: true, data: {} } }), put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: vi.fn(), logout: vi.fn() }),
}))

import AiLlm from '../pages/AiLlm'
import BrowserExt from '../pages/BrowserExt'
import Campaigns from '../pages/Campaigns'
import Cicd from '../pages/Cicd'
import Cloud from '../pages/Cloud'
import Compliance from '../pages/Compliance'
import ContainerPage from '../pages/ContainerPage'
import DatabasePage from '../pages/DatabasePage'
import Firmware from '../pages/Firmware'
import Iac from '../pages/Iac'
import Iam from '../pages/Iam'
import Integrations from '../pages/Integrations'
import Network from '../pages/Network'
import Pentest from '../pages/Pentest'
import Policies from '../pages/Policies'
import Retest from '../pages/Retest'
import SupplyChain from '../pages/SupplyChain'
import ThreatModel from '../pages/ThreatModel'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

const wrappers = [
  { Component: AiLlm, title: 'AI / LLM Security', subtitle: 'LLM Models' },
  { Component: BrowserExt, title: 'Browser Extension Security', subtitle: 'Chrome / Firefox' },
  { Component: Campaigns, title: 'Security Campaigns', subtitle: 'Bug Bounty' },
  { Component: Cicd, title: 'CI/CD Pipeline', subtitle: 'GitHub Actions' },
  { Component: Cloud, title: 'Cloud Security', subtitle: 'AWS / Azure / GCP' },
  { Component: Compliance, title: 'Compliance Frameworks', subtitle: 'SOC2' },
  { Component: ContainerPage, title: 'Container Security', subtitle: 'Docker, Kubernetes' },
  { Component: DatabasePage, title: 'Database Security', subtitle: 'PostgreSQL, MySQL' },
  { Component: Firmware, title: 'Firmware Security', subtitle: 'IoT / Embedded' },
  { Component: Iac, title: 'Infrastructure as Code', subtitle: 'Terraform' },
  { Component: Iam, title: 'IAM & Access Management', subtitle: 'Identity & Access' },
  { Component: Integrations, title: 'Integrations', subtitle: 'SIEM, Slack' },
  { Component: Network, title: 'Network Security', subtitle: 'Firewalls, VPCs' },
  { Component: Pentest, title: 'Penetration Testing', subtitle: 'Engagements' },
  { Component: Policies, title: 'Security Policies', subtitle: 'Rules, Gates' },
  { Component: Retest, title: 'Retest & Verification', subtitle: 'Verify remediation' },
  { Component: SupplyChain, title: 'Supply Chain Security', subtitle: 'Provenance' },
  { Component: ThreatModel, title: 'Threat Modeling', subtitle: 'STRIDE, PASTA' },
]

describe('Thin wrapper pages (EntityListPage)', () => {
  beforeEach(() => { vi.clearAllMocks() })

  wrappers.forEach(({ Component, title, subtitle }) => {
    it(`${title} renders title and subtitle`, async () => {
      render(wrap(<Component />))
      await waitFor(() => {
        expect(screen.getByText(title)).toBeInTheDocument()
        expect(screen.getByText(new RegExp(subtitle))).toBeInTheDocument()
      })
    })
  })

  wrappers.forEach(({ Component, title }) => {
    it(`${title} renders table with data`, async () => {
      mockGet.mockImplementationOnce((url: string) => {
        if (url.includes('/projects')) return Promise.resolve({ data: { success: true, data: { content: [{ id: 'p1', name: 'Test Project', organizationId: 'org1' }] } } })
        return Promise.resolve({ data: { success: true, data: { content: [{ id: '1', name: 'Test Item', status: 'ACTIVE', createdAt: '2026-01-01', findingId: 'FND-001', type: 'SAST', provider: 'AWS', platform: 'GITHUB_ACTIONS', host: '10.0.0.1', port: '443', principalName: 'alice', principalType: 'User', version: '1.0', severity: 'HIGH', scope: 'Target', comment: 'Retest reason', result: 'PASS', fileName: 'firmware.bin', filePath: 'main.tf', repository: 'acme/app' }], totalElements: 1 } } })
      })
      render(wrap(<Component />))
      await waitFor(() => {
        expect(screen.getByText('1 records')).toBeInTheDocument()
      })
    })
  })

  wrappers.filter(w => w.title !== 'Compliance').forEach(({ Component, title }) => {
    it(`${title} renders project selector`, async () => {
      render(wrap(<Component />))
      await waitFor(() => {
        expect(screen.getByDisplayValue('Test Project')).toBeInTheDocument()
      })
    })
  })

  it('AiLlm renders create fields', async () => {
    render(wrap(<AiLlm />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('BrowserExt renders create fields', async () => {
    render(wrap(<BrowserExt />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Campaigns renders create fields', async () => {
    render(wrap(<Campaigns />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Cicd renders create fields', async () => {
    render(wrap(<Cicd />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Cloud renders create fields', async () => {
    render(wrap(<Cloud />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('ContainerPage renders create fields', async () => {
    render(wrap(<ContainerPage />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('DatabasePage renders create fields', async () => {
    render(wrap(<DatabasePage />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Firmware renders create fields', async () => {
    render(wrap(<Firmware />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Iac renders create fields', async () => {
    render(wrap(<Iac />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Iam renders create fields', async () => {
    render(wrap(<Iam />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Integrations renders create fields', async () => {
    render(wrap(<Integrations />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Network renders create fields', async () => {
    render(wrap(<Network />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Pentest renders create fields', async () => {
    render(wrap(<Pentest />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Policies renders create fields', async () => {
    render(wrap(<Policies />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Retest renders create fields', async () => {
    render(wrap(<Retest />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('SupplyChain renders create fields', async () => {
    render(wrap(<SupplyChain />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('ThreatModel renders create fields', async () => {
    render(wrap(<ThreatModel />))
    await waitFor(() => {
      expect(screen.getByText('+ New')).toBeInTheDocument()
    })
  })

  it('Compliance does NOT render + New button (no createFields)', async () => {
    render(wrap(<Compliance />))
    await waitFor(() => {
      expect(screen.getByText('Compliance Frameworks')).toBeInTheDocument()
    })
    expect(screen.queryByText('+ New')).not.toBeInTheDocument()
  })

  it('All wrappers show record count after data loads', async () => {
    render(wrap(<AiLlm />))
    await waitFor(() => {
      expect(screen.getByText('1 records')).toBeInTheDocument()
    })
  })
})
