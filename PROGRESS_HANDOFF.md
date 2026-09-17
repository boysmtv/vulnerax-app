# VulneraX Test Coverage Handoff

## Current State (Sept 17, 2026 — 12:32 PM)
- **Frontend**: 658 tests ALL PASS, 98.9% stmts, 95.66% branch, 98.78% funcs, 100% lines
- **Backend**: 68 tests ALL PASS (risk, identity, finding, report modules)
- **Backend JaCoCo**: 19% overall (modules/report 97%, modules/graph 95%, modules/mobile 81%)

## What Was Fixed This Session
1. **4 broken page imports** — `import api from "../api"` → `import { api } from "../api/client"`:
   - `Coverage.tsx`
   - `AssetGraph.tsx`
   - `Correlation.tsx`
   - `Validation.tsx`

2. **Rewrote `Coverage.tsx`** — old page used `overallCoverage.toFixed()` on wrong data shape. New page:
   - Project selector dropdown
   - Create Demo button
   - Coverage cards with domain/status/percent
   - JSON `<pre>` display
   - Empty state, loading state, error handling

3. **Fixed `Coverage.test.tsx`** — 3 test fixes:
   - `beforeEach` now restores default mock implementation (was lost by `vi.clearAllMocks()`)
   - Changed `mockImplementationOnce` → `mockImplementation` (component makes 2 API calls)
   - Changed `getByText(/TESTED/)` → `getAllByText(/TESTED/)` (multiple elements match)

4. **Fixed `Findings.tsx` collapseAll bug** — `collapseAll()` set `expanded({})` but `isOpen` checked `!== false` (undefined !== false = true), so groups never collapsed. Fixed by explicitly setting all groups to `false`.

5. **Added 12 frontend tests** (Findings expand/collapse/toggle/sort/stats, Coverage error handling, non-TESTED status, CreateDemo with content/null responses, multiple items)

6. **Added 45 backend tests** across 3 new test files:
   - `RiskEngineStaticCalculateTest` (21 tests) — static `calculate()` method with RiskResult
   - `AuthServicePasswordValidationTest` (9 tests) — `validatePasswordStrength()` branches
   - `FindingServiceExtendedTest` (15 tests) — `update()`, evidence creation, correlation, stats null handling

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
| modules/risk | 39% | 28% | IMPROVED (21 new tests for static calculate) |
| modules/finding | 37% | 43% | IMPROVED (15 new tests for update/evidence/correlation) |
| modules/identity | 37% | 28% | IMPROVED (9 new tests for password validation) |
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
- Frontend pages must match test expectations — check test mocks before writing page
- `document.querySelector` returns `null` in tests — prefer `screen` queries
- Backend full test suite times out — run subsets or use `-Dtest=Pattern`
- `assertEquals(0, boxedDouble)` fails — use `assertEquals(0.0, ...)` for type match
- `User.Role` enum has no `ADMIN` — valid values: ORG_OWNER, SECURITY_ADMIN, SECURITY_ENGINEER, PENTESTER, DEVELOPER, TECH_LEAD, AUDITOR, VIEWER, CLIENT
