# VulneraX — Unified Security Engineering & Assessment Platform

> **Single Source of Truth for Technical Security Risk** — Security Control Plane + Scanner Orchestrator + Vulnerability Management + Reverse Engineering Workspace + Risk Intelligence + AI Analyst

![Stack](https://img.shields.io/badge/Backend-Spring%20Boot%203.2%20%7C%20Java%2017-brightgreen) ![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20TypeScript%20%7C%20Tailwind-blue) ![DB](https://img.shields.io/badge/DB-PostgreSQL%2015%20%7C%20Flyway-blue) ![Docker](https://img.shields.io/badge/Docker-Compose%20%7C%20K8s-2496ED)

Product vision: satu platform untuk menemukan, menganalisis, menghubungkan, memprioritaskan, memvalidasi, memperbaiki, dan melaporkan security weakness di 50+ asset types — dari Source Code → Mobile → API → Container → Cloud → Network → Supply Chain.

---

## MVP Scope (PRD #140) — ✅ Implemented

| Domain | PRD Section | Status |
|--------|-------------|--------|
| **Platform Foundation** | #7, #99-102 | Auth JWT, Organization/Workspace/Project hierarchy, multi-tenant, modular monolith |
| **Asset Inventory** | #8-10 | 20+ asset types, CRUD, stats by type/criticality, delta discovery, EASM mock (GitHub/AWS/DNS) |
| **SAST/SCA/Secrets/SBOM** | #11-14 | Scan profiles PASSIVE→PENTEST, mock Semgrep/CodeQL/Trivy/Gitleaks workers, SBOM CycloneDX/SPDX, reachability |
| **API & DAST** | #15-16 | OpenAPI/HAR/Postman import-ready, API inventory, OWASP API Top 10 mapping, browser crawl mock |
| **Mobile & RE** | #17-19, #4 | APK/AAB/IPA upload, manifest/dex/resources, MASVS mapping, RE workspace (strings/symbols/call graph) |
| **Finding Normalization** | #36-39 | Canonical finding (SARIF → canonical JSON), CWE/OWASP/CVSS/EPSS/KEV, confidence, fingerprint |
| **Dedup & Correlation** | #37-38 | Fingerprint dedup → FindingInstance, cross-scanner correlation (SAST+DAST+exposure fusion) |
| **Risk Engine** | #40-42 | CVSS 4.0 + EPSS + KEV + Criticality + Exposure + Reachability + Env + Confidence → 0-100 + SLA (24h/7d/30d/90d) |
| **Security Graph** | #34-35, #104 | Asset→Component→Vuln graph, Attack Path (Internet→Web→API→Service→DB), blast radius |
| **AI Analyst** | #48-51 | Explain / root cause / fix suggestion / code diff / test recommendation / prioritization |
| **Reporting** | #63-73 | Executive/Technical/Developer/Pentest/Retest/Compliance/SupplyChain/Posture, PDF/HTML/JSON/CSV/SARIF, white-label-ready |
| **Orchestrator** | #52-54 | Kafka + isolated workers, plugin architecture (Semgrep, Trivy, ZAP, MobSF), profiles, scope & ownership verification |
| **Dashboard** | #74-79 | Command Center: score, risk, exposed, KEV, SLA, top apps, trend, coverage indicator |
| **Standards** | #5 | OWASP Top10 2025, ASVS 5.0, MASVS/MASWE/MASTG, CVSS 4.0, EPSS, KEV, SARIF 2.1.0, CWE/CVE/CAPEC, CIS, ISO27001 |

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

Default seed user: `admin@vulnerax.io / Admin123!` (sec@vulnerax.io / Sec123!, dev@vulnerax.io / Dev123!)

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

---

## Architecture

```
React (TS, Tailwind, TanStack Query)
        │
    API Gateway (Spring Security + JWT)
        │
Spring Boot Modular Monolith
  ├─ Identity, Organization, Asset, Scan, Finding, Risk, Graph, AI, Reporting, Audit
  ├─ PostgreSQL (Flyway) + Redis + S3 (MinIO) + Kafka
  └─ Scanner Workers (isolated, Kafka-orchestrated)
        │
Finding Normalizer → Deduplication → Correlation → Security Graph → Risk Engine → AI Analyst → Reporting
```

**Recommended Core Stack (PRD #100)**: React + Tailwind + TanStack Query **|** Spring Boot + Spring Security + Modulith **|** PostgreSQL + Redis + MinIO + Kafka **|** Docker/K8s + OTel/Prometheus/Grafana + Vault.

Initial architecture = **Modular Monolith + Independent Scanner Workers + Kafka** (jangan 40 microservices sekaligus).

---

## API Overview (API-First, #105)

| Domain | Endpoint | Method |
|--------|----------|--------|
| Auth | `/api/v1/auth/login`, `/register`, `/me` | POST/GET |
| Org | `/api/v1/organizations`, `/workspaces`, `/projects` | CRUD |
| Assets | `/api/v1/assets`, `/stats`, `/discover` | GET/POST |
| Scans | `/api/v1/scans`, `/{id}/jobs`, `/{id}/cancel` | GET/POST |
| Findings | `/api/v1/findings`, `/{id}/evidence`, `/{id}/correlation`, `/stats` | GET/POST/PUT |
| Risk | via `riskScore` on finding + `/dashboard/posture` | — |
| Graph | `/api/v1/graph`, `/attack-paths` | GET |
| AI | `/api/v1/ai/explain/{findingId}`, `/prioritize`, `/report-draft` | GET |
| Mobile | `/api/v1/mobile`, `/{id}/workspace` | POST/GET |
| SBOM | `/api/v1/sboms` | POST/GET |
| Reports | `/api/v1/reports/generate`, `/{id}/export` | POST/GET |
| Search | `/api/v1/search?q=` | GET |
| Audit | `/api/v1/audit` | GET |
| Docs | `/api-docs`, `/swagger-ui.html` | GET |

Webhook events: `finding.created`, `scan.completed`, `risk.changed`, `asset.discovered`.

---

## Frontend Routes

| Path | Page | PRD Coverage |
|------|------|--------------|
| `/` | Dashboard — Command Center | #74, #118-122 |
| `/projects` | Org/Workspace/Project hierarchy | #7, #141-142 |
| `/assets` | Asset Inventory + discovery delta | #8-10 |
| `/findings` | Vulnerability Explorer + filters | #76, #40-42 |
| `/findings/:id` | Detail: Problem/Impact/Evidence/Fix + AI | #91, #48-51 |
| `/scans` | Scan Center Orchestrator | #79, #52-58 |
| `/mobile` | Mobile RE Workspace | #78, #19 |
| `/graph` | Attack Graph UI | #77, #35 |
| `/reports` | Reporting Engine | #63-73 |

---

## Security Knowledge Graph Example

```
Internet
   ↓
api.acme.com (internetExposed=true)
   ↓
API Gateway
   ↓
payment-service —[vulnerable log4j CVE-2021-44228, KEV, EPSS 0.96]→
   ↓
PostgreSQL (transactions) — contains Confidential
```

Attack Path shows: Entry Point, Affected Assets, Weaknesses, Trust Relationships, Impact, Controls, Risk, Mitigation — evidence-based, no uncontrolled exploitation.

---

## Development Notes

- **Validation**: Flyway V1 + JPA `validate`, global exception handler, BCrypt, JWT HS512, CORS.
- **Observability**: Actuator + Prometheus ready; add OTel/Prom/Grafana/Loki per `docker-compose`.
- **Seed Data**: On first boot creates Org `Acme Financial`, projects `Digital Banking`/`Payment Gateway`, 6 assets, 5 findings (BOLA, SQLi, Secret, Log4Shell, Root container).
- **Scan Mock**: Async jobs (semgrep/codeql/trivy/zap/mobsf etc) → auto-generates findings → risk scoring → graph.
- **SLA**: Critical 24h, High 7d, Medium 30d, Low 90d; adjusted by contextual risk ≥81→1d.

---

## Roadmap Next (PRD #139)

- [ ] Phase 3: Real scanner integration (Semgrep, Trivy, ZAP, MobSF via workers)
- [ ] Phase 5-6: Cloud (AWS/Azure/GCP), K8s RBAC, IAM privilege chain, EPSS daily refresh
- [ ] Phase 7: Postgres→GraphDB when attack-graph complexity requires
- [ ] Phase 9: SSO/SCIM/ABAC, private scanner agent (outbound-only), hybrid/on-prem
- [ ] Phase 10: Firmware/IoT, AI/LLM security testing, custom scanner SDK marketplace

---

## License

Private — Acme Financial Demo. Use `docker compose down -v` to reset.
