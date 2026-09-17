# VulneraX Test Coverage Handoff

## Current State (Sept 17, 2026 — 1:35 PM)
- **Frontend**: 658 tests ALL PASS, 98.9% stmts, 95.66% branch, 98.78% funcs, 100% lines
- **Backend**: 106 tests ALL PASS (risk, identity, finding, report modules subset)
- **Backend JaCoCo**: 19% overall (modules/report 97%, modules/graph 95%, modules/mobile 81%)
- **System Status**: Running locally — backend :8080, frontend :5173
- **Docker Services**: PostgreSQL :5434, Redis :6381, Kafka :9094, Zookeeper

## System Running State
- Backend started via `mvn spring-boot:run` with env vars: DATABASE_URL=jdbc:postgresql://localhost:5434/vulnerax, REDIS_HOST=localhost:6381, KAFKA_BOOTSTRAP=localhost:9094
- Frontend via `npm run dev` on port 5173
- Docker infra: `docker compose up -d postgres redis zookeeper kafka`
- DataSeeder seeds admin@vulnerax.io / Admin12345!abc (ORG_OWNER)
- Login works, dashboard accessible, all features available

## What Was Fixed This Session
1. **4 broken page imports** — `import api from "../api"` → `import { api } from "../api/client"`:
   - `Coverage.tsx`, `AssetGraph.tsx`, `Correlation.tsx`, `Validation.tsx`

2. **Rewrote `Coverage.tsx`** — new page with project selector, Create Demo, coverage cards, JSON pre display

3. **Fixed `Coverage.test.tsx`** — mock restoration, mockImplementationOnce→mockImplementation, getAllByText

4. **Fixed `Findings.tsx` collapseAll bug** — explicitly set all groups to `false`

5. **Added 12 frontend tests** (Findings expand/collapse/toggle/sort/stats, Coverage error handling)

6. **Added 45 backend tests** across 3 new test files:
   - `RiskEngineStaticCalculateTest` (21 tests) — static `calculate()` method
   - `AuthServicePasswordValidationTest` (9 tests) — `validatePasswordStrength()` branches
   - `FindingServiceExtendedTest` (15 tests) — `update()`, evidence, correlation, stats

## Frontend Coverage Detail
| File | Stmts | Branch | Funcs | Lines |
|------|-------|--------|-------|-------|
| Coverage.tsx | 88.09% | 70.83% | 83.33% | 88.88% |
| Dashboard.tsx | 100% | 92.85% | 100% | 100% |
| Findings.tsx | 76.66% | 81.81% | 65.51% | 80% |
| OneClickTest.tsx | 96.07% | 90.9% | 94.44% | 100% |
| Reports.tsx | 96.77% | 85.71% | 100% | 100% |
| Scans.tsx | 95.45% | 100% | 91.66% | 100% |
| Layout.tsx | 100% | 94.44% | 100% | 100% |

## Backend Coverage by Module (from JaCoCo)
| Module | Instr | Branch | Status |
|--------|-------|--------|--------|
| modules/report | 97% | 76% | GOOD |
| modules/graph | 95% | 86% | GOOD |
| modules/mobile | 81% | 74% | GOOD |
| modules/reporting | 44% | 20% | NEEDS WORK |
| modules/risk | 39% | 28% | IMPROVED (21 new tests) |
| modules/finding | 37% | 43% | IMPROVED (15 new tests) |
| modules/identity | 37% | 28% | IMPROVED (9 new tests) |
| modules/scan | 29% | 10% | NEEDS WORK |
| All others | 0% | 0% | NO TESTS |

## Next Steps (Priority Order)
1. **Frontend Findings.tsx** — 76.66% stmts → push to 95%+
2. **Frontend Coverage.tsx** — 88.09% stmts → push to 95%+
3. **Backend reporting** — 44% → add more ReportService/ReportController tests
4. **Backend scan** — 29% → add ScanService/ScanController tests
5. **Backend 0% modules** — prioritized by business value

## Key Pitfalls Learned
- `vi.clearAllMocks()` clears mock implementations too — restore in `beforeEach`
- `mockImplementationOnce` only applies to 1 call — use `mockImplementation` for multi-call components
- `assertEquals(0, boxedDouble)` fails — use `assertEquals(0.0, ...)` for type match
- `User.Role` enum: ORG_OWNER, SECURITY_ADMIN, SECURITY_ENGINEER, PENTESTER, DEVELOPER, TECH_LEAD, AUDITOR, VIEWER, CLIENT
- DataSeeder skips if user count > 0 — delete all users to force re-seed
- Backend full test suite times out — run subsets with `-Dtest=Pattern`
