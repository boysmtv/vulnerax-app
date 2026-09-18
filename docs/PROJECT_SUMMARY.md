# VulneraX - Project Summary (AI Context)

## Overview
**VulneraX** adalah platform keamanan siber terpadu (unified security platform) yang mencakup vulnerability management, pentest orchestration, reverse engineering, DevSecOps, attack surface management, dan risk intelligence engine.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Java 17, Spring Boot 3.2.5, Spring Security, Spring Data JPA |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Zustand, React Query, Recharts |
| Database | PostgreSQL 16 (Flyway migrations) |
| Cache | Redis 7 |
| Messaging | Apache Kafka |
| Object Storage | MinIO (S3-compatible) |
| Auth | JWT (jjwt 0.12.5), BCrypt, MFA (TOTP), SSO (SAML/OIDC/LDAP/SCIM) |
| API Docs | SpringDoc OpenAPI 2.3.0 |
| Build | Maven (backend), npm (frontend) |
| Infra | Docker Compose, Kubernetes |

---

## Project Structure

```
vulnerax-app/
├── backend/
│   ├── src/main/java/com/vulnerax/
│   │   ├── common/          # ApiResponse, BaseEntity, PageResponse, exceptions
│   │   ├── config/          # SecurityConfig, AuditingConfig, OpenApiConfig, RateLimit
│   │   ├── modules/
│   │   │   ├── ai/          # AI Analyst (DeepSeek integration)
│   │   │   ├── aillm/       # AI/LLM asset analysis
│   │   │   ├── assessment/  # Security assessment orchestration
│   │   │   ├── asset/       # Asset management (web, API, mobile, etc.)
│   │   │   ├── audit/       # Audit event logging
│   │   │   ├── browser/     # Browser extension tracking
│   │   │   ├── campaign/    # Security campaigns
│   │   │   ├── cicd/        # CI/CD pipeline integration
│   │   │   ├── cloud/       # Cloud resource scanning
│   │   │   ├── compliance/  # Compliance frameworks (OWASP, NIST, PCI, etc.)
│   │   │   ├── container/   # Container image scanning
│   │   │   ├── coverage/    # Security coverage tracking
│   │   │   ├── dashboard/   # Dashboard aggregation
│   │   │   ├── database/    # Database asset management
│   │   │   ├── finding/     # Finding management (core entity)
│   │   │   ├── firmware/    # Firmware analysis
│   │   │   ├── graph/       # Attack path graph visualization
│   │   │   ├── iac/         # Infrastructure as Code scanning
│   │   │   ├── iam/         # Identity & Access Management
│   │   │   ├── identity/    # Auth (JWT, MFA, SSO, RBAC)
│   │   │   ├── integration/ # Third-party integrations
│   │   │   ├── k8s/         # Kubernetes security
│   │   │   ├── mobile/      # Mobile app analysis (Android/iOS)
│   │   │   ├── network/     # Network asset scanning
│   │   │   ├── notification/# Notification system
│   │   │   ├── oneclick/    # 1-click security test wizard
│   │   │   ├── organization/# Org, Workspace, Project hierarchy
│   │   │   ├── pentest/     # Pentest engagement management
│   │   │   ├── policy/      # Security policy engine
│   │   │   ├── rbac/        # Role-Based Access Control (NEW)
│   │   │   ├── reporting/   # Report generation (PDF, HTML, JSON)
│   │   │   ├── retest/      # Vulnerability retest tracking
│   │   │   ├── risk/        # Risk engine (contextual 0-100 scoring)
│   │   │   ├── sbom/        # Software Bill of Materials
│   │   │   ├── scan/        # Scan orchestration + 8 real analyzers
│   │   │   │   └── analyzers/ # SAST, SCA, Secret, DAST, API, Mobile, Container, IaC
│   │   │   ├── search/      # Global search
│   │   │   ├── supplychain/ # Supply chain provenance + EPSS
│   │   │   └── threatmodel/ # Threat modeling
│   │   └── seed/            # Data seeder
│   ├── src/main/resources/
│   │   ├── application.yml
│   │   └── db/migration/V1__init_schema.sql  # Flyway (NEW)
│   └── src/test/java/       # Unit tests (NEW)
├── frontend/
│   ├── src/
│   │   ├── pages/           # 32 React pages
│   │   ├── components/      # Layout, shared components
│   │   ├── api/             # Axios client
│   │   ├── store/           # Zustand auth store
│   │   └── __tests__/       # Component tests (NEW)
│   └── vitest.config.ts     # Test config (NEW)
├── k8s/                     # Kubernetes manifests (NEW)
│   ├── backend.yaml
│   ├── frontend.yaml
│   └── infrastructure.yaml
├── .github/workflows/ci-cd.yml  # CI/CD pipeline (NEW)
├── docker-compose.yml
├── PRD.md                   # Full PRD (4493 lines)
└── README.md
```

---

## Backend Modules (37)

| Module | Entity/Model | Controller | Service | Description |
|--------|-------------|------------|---------|-------------|
| identity | User, UserRepository | AuthController, MfaController, SsoController | AuthService, JwtTokenProvider, JwtAuthFilter | Auth, JWT, MFA, SSO |
| rbac (NEW) | Permission, RolePermission | - | PermissionService, PermissionAspect | Role-based access control |
| finding | Finding, Evidence, FindingInstance | FindingController | FindingService | Core vulnerability entity |
| scan | Scan, ScanJob | ScanController | ScanService | Scan orchestration |
| asset | Asset | AssetController | AssetService | Asset management |
| organization | Organization, Workspace, Project | OrganizationController | OrganizationService | Multi-tenancy |
| dashboard | - | DashboardController | DashboardService | Aggregation |
| audit | AuditEvent | AuditController | AuditService | Audit logging |
| risk | - | - | RiskEngine | Contextual risk scoring |
| reporting | Report | ReportController | ReportService | Report generation |
| compliance | ComplianceFramework, ComplianceAssessment | ComplianceController | ComplianceService | Compliance tracking |
| policy | SecurityPolicy, PolicyException | PolicyController | PolicyService | Policy engine |
| threatmodel | ThreatModel | ThreatModelController | ThreatModelService | Threat modeling |
| pentest | PentestEngagement | PentestController | PentestService | Pentest management |
| retest | Retest | RetestController | RetestService | Retest tracking |
| cloud | CloudResource | CloudController | CloudService | Cloud scanning |
| k8s | K8sResource | - | K8sService | K8s security |
| iac | IacScan | IacController | IacService | IaC scanning |
| container | ContainerImage | ContainerController | ContainerService | Container scanning |
| mobile | MobileAnalysis | MobileController | MobileService | Mobile analysis |
| network | NetworkAsset | NetworkController | NetworkService | Network scanning |
| database | DatabaseAsset | DatabaseController | DatabaseService | DB scanning |
| cicd | CicdPipeline | CicdController | CicdService | CI/CD integration |
| iam | IamResource | IamController | IamService | IAM management |
| browser | BrowserExtension | BrowserController | BrowserService | Browser extension |
| firmware | FirmwareAsset | FirmwareController | FirmwareService | Firmware analysis |
| integration | Integration | IntegrationController | IntegrationService | Third-party |
| notification | Notification | NotificationController | NotificationService | Notifications |
| coverage | SecurityCoverage | CoverageController | CoverageService | Coverage tracking |
| campaign | SecurityCampaign | CampaignController | CampaignService | Campaigns |
| supplychain | ArtifactProvenance | ProvenanceController | ProvenanceService | Supply chain |
| aillm | AiAsset | AiLlmController | AiLlmService | AI/LLM analysis |
| ai | - | AiController | AiAnalystService | AI analyst |
| sbom | Sbom | SbomController | SbomService | SBOM generation |
| oneclick | OneClickRun | OneClickController | OneClickService | 1-click wizard |
| search | - | SearchController | - | Global search |
| graph | - | GraphController | SecurityGraphService | Attack path graph |

---

## API Endpoints (Key)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/v1/auth/register | Public | Register user |
| POST | /api/v1/auth/login | Public | Login |
| GET | /api/v1/auth/me | JWT | Current user |
| POST | /api/v1/auth/mfa/setup | JWT | Setup MFA |
| GET | /api/v1/organizations | JWT | List orgs |
| GET | /api/v1/projects | JWT | List projects |
| GET | /api/v1/findings | JWT + FINDINGS_READ | List findings |
| POST | /api/v1/findings | JWT + FINDINGS_WRITE | Create finding |
| PUT | /api/v1/findings/{id}/status | JWT + FINDINGS_APPROVE | Update status |
| GET | /api/v1/findings/stats | JWT + FINDINGS_READ | Finding stats |
| GET | /api/v1/scans | JWT + SCANS_READ | List scans |
| POST | /api/v1/scans | JWT + SCANS_WRITE | Create scan |
| POST | /api/v1/scans/upload | JWT + SCANS_WRITE | Upload & scan |
| GET | /api/v1/dashboard/posture | JWT | Dashboard |
| GET | /api/v1/graph/attack-paths | JWT | Attack paths |
| GET | /api/v1/search | JWT | Global search |
| GET | /api/v1/audit | JWT | Audit logs |
| GET | /actuator/health | Public | Health check |
| GET | /swagger-ui.html | Public | API docs |

---

## Security Features

1. **Authentication**: JWT with refresh tokens, BCrypt password hashing
2. **Authorization**: RBAC with 24 permissions, 7 roles (ORG_OWNER → VIEWER)
3. **MFA**: TOTP-based (QR code generation)
4. **SSO**: SAML, OIDC, LDAP, SCIM support
5. **Rate Limiting**: 60 req/min, 1000 req/hour per IP
6. **Audit Logging**: All state changes tracked
7. **Input Validation**: Jakarta Bean Validation
8. **CORS**: Configurable allowed origins

---

## Risk Engine

Contextual scoring 0-100 based on:
- CVSS score (up to 30 points)
- EPSS exploitation probability (up to 15)
- KEV active exploitation (+12)
- Business criticality (2-15)
- Internet exposure (+12)
- Reachability (+8)
- Environment (prod +5)
- Confidence level (-5 to +5)
- Severity weight (0-10)
- Age factor (up to 5)

Risk levels: LOW (0-20), MODERATE (21-40), HIGH (41-60), VERY_HIGH (61-80), CRITICAL (81-100)

SLA: CRITICAL 24h, HIGH 7d, MEDIUM 30d, LOW 90d

---

## Real Analyzers (8)

| Analyzer | Type | What it detects |
|----------|------|-----------------|
| SastAnalyzer | SAST | SQL injection, XSS, command injection, path traversal |
| ScaAnalyzer | SCA | Vulnerable dependencies, CVE mapping, EPSS/KEV |
| SecretAnalyzer | Secret | Hardcoded API keys, passwords, tokens, private keys |
| DastAnalyzer | DAST | Missing security headers, XSS, SQLi, open redirects |
| ApiAnalyzer | API | API-specific vulnerabilities, broken auth, mass assignment |
| MobileAnalyzer | Mobile | Insecure storage, weak crypto, exposed components |
| ContainerAnalyzer | Container | Running as root,latest tag, secrets in env, writable fs |
| IaCAnalyzer | IaC | Terraform misconfig, public S3, open security groups |

---

## Git History

```
2b06d55 feat: RBAC, Flyway migrations, rate limiting, tests, CI/CD, k8s
01f9095 feat: 8 real security analyzers, 1-click wizard, rollback fix, 42 attack domains
6cd1717 feat: VulneraX 100% PRD - Unified Security Platform MVP + Real analyzers + DeepSeek + Assessment orchestration
```

---

## What's Done

- [x] Full project scaffold (37 backend modules, 32 frontend pages)
- [x] JWT auth with MFA/SSO support
- [x] RBAC with 24 permissions, 7 roles
- [x] Flyway database migrations (25+ tables)
- [x] 8 real security analyzers
- [x] 1-click wizard orchestration
- [x] Risk engine with contextual scoring
- [x] Rate limiting
- [x] Enhanced error handling
- [x] Backend unit tests (5 test classes)
- [x] Frontend component tests (3 test files)
- [x] GitHub Actions CI/CD pipeline
- [x] Kubernetes deployment manifests
- [x] Data seeder
- [x] Swagger/OpenAPI docs

---

## What Could Be Improved

- [ ] Integration with real security tools (Trivy, Semgrep, Nmap CLI)
- [ ] WebSocket for real-time scan updates
- [ ] PDF/HTML report generation with templates
- [ ] Email notification system
- [ ] Multi-factor authentication TOTP validation (currently demo)
- [ ] Organization-level data isolation in queries
- [ ] Pagination optimization for large datasets
- [ ] Frontend E2E tests (Cypress/Playwright)
- [ ] Performance/load testing
- [ ] Terraform/Pulumi for infrastructure
- [ ] Prometheus metrics custom dashboards
- [ ] Log aggregation (ELK/Loki)

---

## Running Locally

```bash
# Start infrastructure
docker-compose up -d

# Backend
cd backend && mvn spring-boot:run

# Frontend
cd frontend && npm install && npm run dev
```

---

## Key Files

| File | Purpose |
|------|---------|
| `../PRD.md` | Full PRD (4493 lines) |
| `backend/src/main/resources/db/migration/V1__init_schema.sql` | Database schema |
| `backend/src/main/java/com/vulnerax/modules/rbac/` | RBAC system |
| `backend/src/main/java/com/vulnerax/config/ratelimit/RateLimitFilter.java` | Rate limiting |
| `backend/src/main/java/com/vulnerax/common/exception/GlobalExceptionHandler.java` | Error handling |
| `backend/src/main/java/com/vulnerax/modules/scan/ScanService.java` | Scan orchestration |
| `backend/src/main/java/com/vulnerax/modules/finding/FindingService.java` | Finding management |
| `backend/src/main/java/com/vulnerax/modules/risk/RiskEngine.java` | Risk scoring |
| `.github/workflows/ci-cd.yml` | CI/CD pipeline |
| `k8s/` | Kubernetes manifests |
