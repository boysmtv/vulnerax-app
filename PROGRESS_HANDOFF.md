# VulneraX Test Coverage Handoff

## Current State (Sept 18, 2026 — 12:35 PM)
- **Frontend**: 658 tests ALL PASS (39 files), Findings.tsx + Coverage.tsx verified 100% stmts / 100% funcs / 100% lines (target 95%+ EXCEEDED)
- **Backend**: 56 tests ALL PASS (reporting 48 + scan controller 8) — ReportControllerTest fixed (2 errors → 0)
- **Backend JaCoCo (reporting)**: ReportController 0% → 85.6% instr, 100% lines; ReportService ~98% (3 missed)
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
1. ~~Frontend Findings.tsx — 76.66% stmts → push to 95%+~~ DONE (100% stmts verified Sept 18)
2. ~~Frontend Coverage.tsx — 88.09% stmts → push to 95%+~~ DONE (100% stmts verified Sept 18)
3. ~~Backend reporting — 44% → add more ReportService/ReportController tests~~ DONE (ReportController 92.1% instr/100% lines, 18 new unit tests + fixed 2 WebMvcTest errors)
4. ~~Backend scan ScanService 0%~~ DONE 67.5% (20 new unit tests: list/get/jobs/create/pluginsFor/start/cancel/kafka/executeAsync legacy+plugin paths)
5. ~~Backend scan plugins 0%~~ DONE: Secret 100%, Registry 100%, Sca 99.4%, Sast 96.8%, Container 90.3%, Iac 88.5%, Mobile 88% (12 new tests; Dast 35.5%/Api 34.7% network-bound, plan/validate covered)
6. ~~Backend controllers 0%~~ DONE: Mfa 100% (11 tests), EvidenceService 96.9% (7 tests), FindingController 91.1% (4 tests), AuthController 86.7% (6 tests), ScanController 100% (8 tests), SlaBreachScheduler 100% (7 tests)
7. ~~Sisa (opsional, network-bound): DastAnalyzer 1%, ApiAnalyzer 0%~~ DONE via JDK HttpServer stubs (pola AiAnalystServiceDeepSeekTest): DastAnalyzer 85.7% (10 tests, 25 asersi temuan), ApiAnalyzer 92.4%, DastPlugin 94.1%, ApiPlugin 90.7%. **Bug produksi ditemukan & diperbaiki**: `Map.of("response", null)` + `Map.of("error", null)` NPE di path Target-Unreachable (DastAnalyzer.java) — path itu tidak pernah bisa jalan sebelumnya.
8. ~~Container 55% / Mobile 53% / IaC 29%~~ DONE via `MiscAnalyzersTest` (21 tests): Container 99.3%, Mobile 99.0%, IaC 96.7%. **Bug produksi #2 ditemukan & diperbaiki**: cek secret Dockerfile `"ENV "+s` vs `config.toLowerCase()` — dead code, tidak pernah match (ContainerAnalyzer.java → `"env "/"arg "`).
9. ~~ScaAnalyzer 64%~~ DONE via `ScaAnalyzerTest` (12 tests: maven/npm/pip/go/generic/null-file): **99.0%**.
10. ~~Full suite~~ DONE: `mvn test` 1992 tests (8:42 mnt) → 37 failures + 2 errors, **semua diperbaiki**: 36 fixture AiAnalystService* tak set konfirmasi (guard SCAN_ERROR/commit 57ce2b8 membuat stale) + branch rootCause SCA tak ada (ditambah: "Transitive vulnerable dependency") + 1 ekspektasi stale MEDIUM→INFO (DastPluginCoverageTest) + 2 missing-mock CoverageControllerTest (pola LESSON-009). Verifikasi: 101/101 hijau di 5 kelas yang terdampak; sisa suite sudah hijau di run penuh.
11. **Sisa nyata: tidak ada. Full suite hijau komposisional. Berikutnya (opsional): ScaAnalyzer 99%→100% (5 instr), ScanService 67.5%→80%+, Container/Mobile/IaC plugin execute-paths.**

## Key Pitfalls Learned
- `vi.clearAllMocks()` clears mock implementations too — restore in `beforeEach`
- `mockImplementationOnce` only applies to 1 call — use `mockImplementation` for multi-call components
- `assertEquals(0, boxedDouble)` fails — use `assertEquals(0.0, ...)` for type match
- `User.Role` enum: ORG_OWNER, SECURITY_ADMIN, SECURITY_ENGINEER, PENTESTER, DEVELOPER, TECH_LEAD, AUDITOR, VIEWER, CLIENT
- DataSeeder skips if user count > 0 — delete all users to force re-seed
- Backend full test suite times out — run subsets with `-Dtest=Pattern`
