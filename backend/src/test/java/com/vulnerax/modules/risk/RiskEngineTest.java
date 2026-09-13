import { describe, it, expect } from 'vitest'
import { RiskEngine } from '../../modules/risk/RiskEngine'
import { Finding } from '../../modules/finding/Finding'

describe('RiskEngine', () => {
  const engine = new RiskEngine()

  const baseFinding = {
    cvss: 7.5,
    epss: 0.5,
    kev: false,
    businessCriticality: 'HIGH',
    internetExposed: false,
    reachable: false,
    environment: 'PRODUCTION',
    confidence: 'HIGH',
    severity: 'HIGH',
    createdAt: new Date(),
  } as Finding

  it('calculates risk score with all factors', () => {
    const score = engine.calculate(baseFinding)
    expect(score).toBeGreaterThan(0)
    expect(score).toBeLessThanOrEqual(100)
  })

  it('returns higher score for critical severity', () => {
    const critical = { ...baseFinding, severity: 'CRITICAL', cvss: 9.8 }
    const low = { ...baseFinding, severity: 'LOW', cvss: 2.0 }

    const criticalScore = engine.calculate(critical)
    const lowScore = engine.calculate(low)

    expect(criticalScore).toBeGreaterThan(lowScore)
  })

  it('increases score for KEV exploitation', () => {
    const withKev = { ...baseFinding, kev: true }
    const withoutKev = { ...baseFinding, kev: false }

    const kevScore = engine.calculate(withKev)
    const noKevScore = engine.calculate(withoutKev)

    expect(kevScore).toBeGreaterThan(noKevScore)
  })

  it('increases score for internet exposed assets', () => {
    const exposed = { ...baseFinding, internetExposed: true }
    const notExposed = { ...baseFinding, internetExposed: false }

    const exposedScore = engine.calculate(exposed)
    const notExposedScore = engine.calculate(notExposed)

    expect(exposedScore).toBeGreaterThan(notExposedScore)
  })

  it('returns correct risk level for high scores', () => {
    expect(engine.level(85)).toBe('CRITICAL')
    expect(engine.level(65)).toBe('VERY_HIGH')
    expect(engine.level(45)).toBe('HIGH')
    expect(engine.level(25)).toBe('MODERATE')
    expect(engine.level(10)).toBe('LOW')
  })

  it('enriches finding with risk score and level', () => {
    const finding = { ...baseFinding } as Finding
    engine.enrich(finding)

    expect(finding.riskScore).toBeGreaterThan(0)
    expect(finding.riskLevel).toBeDefined()
    expect(finding.slaDueAt).toBeDefined()
    expect(finding.slaStatus).toBe('WITHIN_SLA')
    expect(finding.fingerprint).toBeDefined()
  })

  it('generates fingerprint for dedup', () => {
    const finding = { ...baseFinding, assetId: 'asset-1', type: 'SAST', cwe: 'CWE-89', filePath: 'test.java', lineNumber: 10 } as Finding
    engine.enrich(finding)

    expect(finding.fingerprint).toMatch(/^[a-f0-9]+$/)
  })
})
