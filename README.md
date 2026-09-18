# VulneraX — Unified Security Engineering & Assessment Platform

> **Single Source of Truth for Technical Security Risk** — Security Control Plane + Scanner Orchestrator + Vulnerability Management + Risk Intelligence + AI Analyst

![Status](https://img.shields.io/badge/Status-Stable%20%7C%20Production%20Ready-brightgreen) ![Backend](https://img.shields.io/badge/Backend-Spring%20Boot%203.2%20%7C%20Java%2017-brightgreen) ![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20TypeScript%20%7C%20Tailwind-blue) ![DB](https://img.shields.io/badge/DB-PostgreSQL%2015%20%7C%20Flyway-blue) ![Infra](https://img.shields.io/badge/Infra-Docker%20Compose%20%7C%20K8s-2496ED)

Product vision: satu platform untuk menemukan, menganalisis, menghubungkan, memprioritaskan, memvalidasi, memperbaiki, dan melaporkan security weakness di 50+ asset types — dari Source Code → Mobile → API → Container → Cloud → Network → Supply Chain.

---

## Production Status — ✅ Stable

| Gate | Result |
|------|--------|
| **Backend tests** | **1992 passed, 0 failures** (`mvn test`, ~9 min) |
| **Backend coverage (JaCoCo)** | **80.1% instructions · 68.1% branches · 82.8% lines** |
| **Frontend tests** | **658 passed, 0 failures** (`npm run test`, 39 files) |
| **Frontend coverage** | **~99% statements · ~96% branches · 100% lines** |
| **Scanner analyzers** | SAST 97.6% · Secret 95.9% · DAST 85.7% · API 92.4% · Container 99.3% · Mobile 99% · IaC 96.7% · SCA 99% |
| **Migrations** | Flyway versioned (`V1__init_schema.sql` + follow-ups), JPA `validate` |
| **CI/CD** | GitHub Actions (`.github/workflows/ci-cd.yml`) — lint, test, build, image |
| **Deployment** | Docker Compose + Kubernetes manifests (`k8s/`) |
| **Observability** | Actuator, Prometheus/Grafana/OTel configs (`monitoring/`) |

> Angka di atas hasil run penuh yang terverifikasi, bukan target. Lihat `PROGRESS_HANDOFF.md` untuk riwayat sesi dan `docs/` untuk analisis mendalam.

---

## What It Does

| Capability | Implementation |
|------------|----------------|
| **8 real scanner analyzers** | SAST (30+ pola), SCA (CVE/EPSS/KEV DB), Secrets, DAST (25+ live HTTP checks), API, Container, IaC, Mobile — murni analisis real, tanpa mock |
| **Plugin architecture** | `SecurityScannerPlugin` + auto-discovery registry (`plan`/`execute`/`normalize`/`validate`) |
| **One-click testing** | Wizard 3 langkah, 8 scanner paralel, progress per-scanner, report otomatis |
| **Finding lifecycle** | Normalisasi SARIF→canonical, dedup fingerprint SHA-256, korelasi fuzzy + CWE/asset, validation gate, retest |
| **Risk engine** | CVSS 4.0 + EPSS + KEV + criticality + exposure + reachability + environment → skor 0–100 + SLA (24h/7d/30d/90d) |
| **Security graph** | Node asset→finding real, edge berbasis CWE (12 aturan rantai), BFS attack path, paginated |
| **Coverage registry** | 30 test WSTG + SAST/SCA/Secret, mapping OWASP ASVS, persentase real (bukan hardcode) |
| **AI Analyst** | Explain / root cause / impact / remediation / code fix / priority (DeepSeek optional, rule-based fallback) |
| **Reporting** | PDF real (OpenPDF) + HTML/JSON/CSV/SARIF, executive & technical, compliance mapping |
| **Auth & tenancy** | JWT + refresh, MFA TOTP (RFC 6238) + recovery codes, SSO (SAML/OIDC/LDAP/SCIM), RBAC 24 permission/7 role, isolasi organisasi di query layer |
| **Hardening** | Rate limiting (60/mnt, 1000/jam), audit logging semua state change, validasi input, CORS dinamis |

---

## Quick Start

### Docker (Recommended — Full Stack)

```bash
docker compose up --build
# Frontend → http://localhost:3000  (nginx proxies /api → backend)
# Backend  → http://localhost:8080 (swagger: /swagger-ui.html)
# MinIO    → http://localhost:9001  (minioadmin/minioadmin)
# Postgres → localhost:5432 (vulnerax/vulnerax)
```

Default seed user: `admin@vulnerax.io / Admin12345!abc`

### Local Dev

**Backend**
```bash
cd backend
mvn spring-boot:run
# or: mvn package -DskipTests && java -jar target/vulnerax-platform-1.0.0.jar
```

**Frontend**
```bash
cd frontend
npm install
npm run dev # → http://localhost:5173 (proxies /api to :8080)
```

**Verify**
```bash
cd backend && mvn test          # 1992 tests, ~9 min
cd frontend && npm run test     # 658 tests
```

---

## Architecture

```
React (TS, Tailwind, TanStack Query)
        │
API Gateway (Spring Security + JWT + RBAC + Rate Limit)
        │
Spring Boot Modular Monolith
  ├─ Identity, Organization, Asset, Scan, Finding, Risk, Graph, AI, Reporting, Audit
  ├─ PostgreSQL (Flyway) + Redis + S3 (MinIO) + Kafka (optional in dev)
  └─ 8 real analyzer plugins (isolated via plugin interface + registry)
        │
Finding Normalizer → Deduplication → Correlation → Security Graph → Risk Engine → AI Analyst → Reporting
```

---

## API Overview (API-First)

| Domain | Endpoint | Method |
|--------|----------|--------|
| Auth | `/api/v1/auth/login`, `/register`, `/me`, `/mfa/*` | POST/GET |
| Org | `/api/v1/organizations`, `/workspaces`, `/projects` | CRUD |
| Assets | `/api/v1/assets`, `/stats`, `/discover` | GET/POST |
| Scans | `/api/v1/scans`, `/{id}/jobs`, `/{id}/cancel`, `/upload` | GET/POST |
| Findings | `/api/v1/findings`, `/{id}/evidence`, `/{id}/correlation`, `/stats` | GET/POST/PUT |
| Risk | via `riskScore` on finding + `/dashboard/posture` | — |
| Graph | `/api/v1/graph`, `/attack-paths` | GET |
| AI | `/api/v1/ai/explain/{findingId}`, `/prioritize`, `/report-draft` | GET |
| Coverage | `/api/v1/coverage` | GET/POST |
| Mobile | `/api/v1/mobile`, `/{id}/workspace` | POST/GET |
| SBOM | `/api/v1/sboms` | POST/GET |
| Reports | `/api/v1/reports/generate`, `/{id}/export` | POST/GET |
| Search | `/api/v1/search?q=` | GET |
| Audit | `/api/v1/audit` | GET |
| Docs | `/api-docs`, `/swagger-ui.html` | GET |

Full contract: [`docs/openapi.yaml`](docs/openapi.yaml).

---

## Docs

| Doc | Content |
|-----|---------|
| [`PRD.md`](PRD.md) | Full PRD (4493 lines) |
| [`PROGRESS_HANDOFF.md`](PROGRESS_HANDOFF.md) | Session handoff — status, coverage, next steps |
| [`docs/PROJECT_SUMMARY.md`](docs/PROJECT_SUMMARY.md) | Module catalog, endpoints, risk engine |
| [`docs/CODE_REALITY_ANALYSIS.md`](docs/CODE_REALITY_ANALYSIS.md) | Honest code-vs-docs audit trail |
| [`docs/openapi.yaml`](docs/openapi.yaml) | OpenAPI contract |

---

## Frontend Routes

| Path | Page |
|------|------|
| `/` | Dashboard — Command Center |
| `/projects` | Org/Workspace/Project hierarchy |
| `/assets` | Asset Inventory + discovery delta |
| `/findings` | Vulnerability Explorer + filters |
| `/findings/:id` | Detail: Problem/Impact/Evidence/Fix + AI |
| `/scans` | Scan Center Orchestrator |
| `/mobile` | Mobile RE Workspace |
| `/graph` | Attack Graph UI |
| `/reports` | Reporting Engine |

---

## Operations

- **Validation**: Flyway + JPA `validate`, global exception handler, BCrypt, JWT, CORS.
- **Observability**: Actuator + Prometheus ready; OTel/Prom/Grafana/Loki per `docker-compose` & `monitoring/`.
- **Seed Data**: First boot creates admin org + demo projects (no mock findings — all data comes from real scans).
- **SLA**: Critical 24h, High 7d, Medium 30d, Low 90d; auto-escalation + breach scheduler every 5 min.
- **Kafka**: event pipeline (`scan.queued/running/completed/failed/cancelled`); auto-disabled when broker unreachable (local dev safe).

---

## Roadmap

- [ ] Real-tool workers (Semgrep, Trivy, ZAP, MobSF binaries behind plugin interface)
- [ ] Cloud (AWS/Azure/GCP), K8s RBAC, IAM privilege chain, EPSS daily refresh
- [ ] Postgres→GraphDB when attack-graph complexity requires
- [ ] SSO/SCIM/ABAC hardening, private scanner agent (outbound-only), hybrid/on-prem
- [ ] Firmware/IoT, AI/LLM security testing, custom scanner SDK marketplace

---

## License

Private — Acme Financial Demo. Use `docker compose down -v` to reset.
