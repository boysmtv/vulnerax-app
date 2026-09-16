import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAuth } from './store/auth'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import Assets from './pages/Assets'
import Scans from './pages/Scans'
import Projects from './pages/Projects'
import Mobile from './pages/Mobile'
import Graph from './pages/Graph'
import Reports from './pages/Reports'
import ThreatModel from './pages/ThreatModel'
import Pentest from './pages/Pentest'
import Compliance from './pages/Compliance'
import Policies from './pages/Policies'
import Retest from './pages/Retest'
import Cloud from './pages/Cloud'
import K8s from './pages/K8s'
import Iac from './pages/Iac'
import Network from './pages/Network'
import DatabasePage from './pages/DatabasePage'
import Cicd from './pages/Cicd'
import Iam from './pages/Iam'
import ContainerPage from './pages/ContainerPage'
import AiLlm from './pages/AiLlm'
import BrowserExt from './pages/BrowserExt'
import Firmware from './pages/Firmware'
import Integrations from './pages/Integrations'
import Notifications from './pages/Notifications'
import Coverage from './pages/Coverage'
import Campaigns from './pages/Campaigns'
import SupplyChain from './pages/SupplyChain'
import OneClickTest from './pages/OneClickTest'
import CorrelationPage from './pages/Correlation'
import AssetGraphPage from './pages/AssetGraph'
import ValidationPage from './pages/Validation'

const qc = new QueryClient()

function Guard({ children }: { children: React.ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  return <Layout>{children}</Layout>
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Guard><OneClickTest /></Guard>} />
          <Route path="/dashboard" element={<Guard><Dashboard /></Guard>} />
          <Route path="/projects" element={<Guard><Projects /></Guard>} />
          <Route path="/assets" element={<Guard><Assets /></Guard>} />
          <Route path="/findings" element={<Guard><Findings /></Guard>} />
          <Route path="/findings/:id" element={<Guard><FindingDetail /></Guard>} />
          <Route path="/scans" element={<Guard><Scans /></Guard>} />
          <Route path="/mobile" element={<Guard><Mobile /></Guard>} />
          <Route path="/graph" element={<Guard><Graph /></Guard>} />
          <Route path="/reports" element={<Guard><Reports /></Guard>} />
          <Route path="/threat-model" element={<Guard><ThreatModel /></Guard>} />
          <Route path="/pentest" element={<Guard><Pentest /></Guard>} />
          <Route path="/compliance" element={<Guard><Compliance /></Guard>} />
          <Route path="/policies" element={<Guard><Policies /></Guard>} />
          <Route path="/retest" element={<Guard><Retest /></Guard>} />
          <Route path="/cloud" element={<Guard><Cloud /></Guard>} />
          <Route path="/k8s" element={<Guard><K8s /></Guard>} />
          <Route path="/iac" element={<Guard><Iac /></Guard>} />
          <Route path="/network" element={<Guard><Network /></Guard>} />
          <Route path="/databases" element={<Guard><DatabasePage /></Guard>} />
          <Route path="/cicd" element={<Guard><Cicd /></Guard>} />
          <Route path="/iam" element={<Guard><Iam /></Guard>} />
          <Route path="/containers" element={<Guard><ContainerPage /></Guard>} />
          <Route path="/ai-llm" element={<Guard><AiLlm /></Guard>} />
          <Route path="/browser" element={<Guard><BrowserExt /></Guard>} />
          <Route path="/firmware" element={<Guard><Firmware /></Guard>} />
          <Route path="/integrations" element={<Guard><Integrations /></Guard>} />
          <Route path="/notifications" element={<Guard><Notifications /></Guard>} />
          <Route path="/coverage" element={<Guard><Coverage /></Guard>} />
          <Route path="/campaigns" element={<Guard><Campaigns /></Guard>} />
          <Route path="/supply-chain" element={<Guard><SupplyChain /></Guard>} />
          <Route path="/one-click" element={<Guard><OneClickTest /></Guard>} />
          <Route path="/correlation" element={<Guard><CorrelationPage /></Guard>} />
          <Route path="/asset-graph" element={<Guard><AssetGraphPage /></Guard>} />
          <Route path="/validation" element={<Guard><ValidationPage /></Guard>} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
