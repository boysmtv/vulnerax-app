# Product Requirements Document

## Unified Security Engineering & Assessment Platform

**Document Version:** 1.0
**Product Type:** Enterprise Cybersecurity Platform
**Primary Interface:** Web Application
**Deployment:** SaaS, Private Cloud, Hybrid, On-Premise
**Primary Goal:** Unified Security Assessment, Vulnerability Management, Pentest Orchestration, Reverse Engineering, DevSecOps, Attack Surface & Risk Management

---

# 1. Executive Summary

Platform ini adalah centralized security platform untuk menemukan, menganalisis, menghubungkan, memprioritaskan, memvalidasi, memperbaiki, dan melaporkan security weakness pada seluruh landscape teknologi organisasi.

Platform tidak terbatas pada web application.

Target cakupan:

* Source Code
* Frontend
* Backend
* Web Application
* REST API
* GraphQL
* gRPC
* WebSocket
* Android
* iOS
* Desktop Application
* Binary
* Native Library
* Container
* Kubernetes
* Cloud
* Server
* Network
* Infrastructure as Code
* CI/CD
* Software Supply Chain
* Dependencies
* Secrets
* Identity & IAM
* Database
* Object Storage
* Serverless
* Browser Extension
* Firmware
* IoT
* AI/LLM Application
* SaaS Configuration
* External Attack Surface

Platform bertindak sebagai:

**Security Control Plane + Security Scanner Orchestrator + Vulnerability Management Platform + Reverse Engineering Workspace + Risk Intelligence Engine + AI Security Analyst.**

Platform bukan hanya menghasilkan daftar vulnerability.

Platform harus mampu menjawab:

> Apa yang rentan?

> Di mana letaknya?

> Mengapa vulnerability tersebut terjadi?

> Apakah benar-benar reachable?

> Apakah aset tersebut exposed ke internet?

> Apakah vulnerability sudah pernah dieksploitasi di dunia nyata?

> Asset apa yang dapat terdampak?

> Seberapa besar dampak bisnisnya?

> Apakah terdapat attack path menuju critical system?

> Apa root cause-nya?

> Siapa yang harus memperbaikinya?

> Bagaimana cara memperbaikinya?

> Apakah fix yang dilakukan developer benar?

> Apakah vulnerability muncul kembali?

> Bagaimana security posture organisasi berubah dari waktu ke waktu?

---

# 2. Product Vision

Membangun satu platform yang dapat menjadi:

> **Single Source of Truth for Technical Security Risk.**

Daripada security engineer menggunakan puluhan aplikasi secara terpisah:

```text
SAST
SCA
DAST
Mobile Scanner
Cloud Scanner
Network Scanner
Secret Scanner
Container Scanner
Pentest Tool
Reverse Engineering Tool
SBOM Tool
Ticketing
Spreadsheet
Reporting
Risk Dashboard
```

platform menggabungkannya menjadi:

```text
                       SECURITY PLATFORM

                            Assets
                              │
                              ▼
                       Asset Inventory
                              │
                              ▼
                    Security Orchestrator
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   Static Analysis       Runtime Analysis     Infrastructure
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                       Finding Engine
                              │
                              ▼
                       Correlation Engine
                              │
                              ▼
                       Risk Engine
                              │
                              ▼
                    Attack Path Analysis
                              │
                              ▼
                     AI Security Analyst
                              │
                              ▼
                Remediation & Verification
                              │
                              ▼
                      Reporting Engine
```

---

# 3. Problem Statement

Modern organization mempunyai security data yang tersebar.

Satu project dapat memiliki:

```text
React Frontend
        ↓
API Gateway
        ↓
Spring Boot
        ↓
Kafka
        ↓
Microservices
        ↓
PostgreSQL
        ↓
Redis
        ↓
Kubernetes
        ↓
AWS
```

Pada saat bersamaan memiliki:

```text
Android App
iOS App
Admin Dashboard
Internal Portal
Third-party API
CI/CD
Docker Images
Terraform
Secrets
Certificates
Cloud IAM
```

Satu vulnerability scanner biasanya hanya melihat sebagian kecil dari sistem tersebut.

Akibatnya:

* temuan terfragmentasi;
* duplicate finding tinggi;
* false positive tinggi;
* security team sulit mengetahui prioritas sebenarnya;
* developer mendapatkan terlalu banyak alert;
* hubungan antar-vulnerability tidak terlihat;
* remediation sulit dilacak;
* laporan pentest dibuat manual;
* hasil scanner berbeda format;
* security posture sulit diukur secara keseluruhan.

Platform ini menyelesaikan masalah tersebut.

---

# 4. Core Product Principles

## 4.1 Detect

Temukan weakness, vulnerability, misconfiguration, exposure, dan insecure implementation.

## 4.2 Understand

Pahami context, source, component, asset, architecture, dan root cause.

## 4.3 Correlate

Gabungkan berbagai temuan menjadi satu security context.

## 4.4 Prioritize

Prioritas berdasarkan actual risk, bukan severity semata.

## 4.5 Validate

Lakukan controlled validation terhadap finding dalam scope yang telah diotorisasi.

## 4.6 Remediate

Berikan developer actionable remediation.

## 4.7 Verify

Scan ulang dan pastikan vulnerability benar-benar telah diperbaiki.

## 4.8 Monitor

Pantau perubahan security posture secara berkelanjutan.

## 4.9 Report

Sediakan report berbeda untuk technical team, executive, auditor, customer, dan regulator.

---

# 5. Security Standards & Knowledge Base

Platform harus memiliki versioned Security Knowledge Base.

Baseline utama:

### Web Application

OWASP Top 10 2025 merupakan versi OWASP Top 10 yang saat ini dirilis.

### Application Security

OWASP ASVS stable saat ini adalah **5.0.0** dan requirement identifier dapat digunakan secara programmatic.

### API Security

OWASP API Security Top 10 2023 mencakup antara lain BOLA, Broken Authentication, Broken Object Property Level Authorization, resource consumption, BFLA, SSRF, misconfiguration dan API inventory.

### Mobile

Gunakan:

* OWASP MASVS
* OWASP MASWE
* OWASP MASTG

MASVS mencakup storage, cryptography, authentication, network, platform interaction, code, reverse-engineering resilience, dan privacy.

### Secure SDLC

NIST SSDF SP 800-218 v1.1 menjadi salah satu baseline secure software development.

### Vulnerability Severity

CVSS 4.0.

CVSS 4.0 memisahkan Base, Threat, Environmental dan Supplemental metrics.

### Exploitation Probability

EPSS.

EPSS memperkirakan probabilitas CVE akan dieksploitasi di dunia nyata dalam 30 hari dan diperbarui secara berkala.

### Known Exploitation

CISA Known Exploited Vulnerabilities Catalog digunakan sebagai salah satu prioritization signal untuk CVE yang diketahui telah dieksploitasi.

### Finding Interoperability

SARIF 2.1.0 sebagai salah satu format interoperabilitas static analysis results.

Platform juga harus mendukung mapping ke:

```text
CVE
CWE
CAPEC
CPE
OWASP
MITRE ATT&CK
NIST
PCI DSS
ISO 27001
SOC 2
CIS Benchmarks
GDPR controls
HIPAA controls
MASVS
ASVS
SSDF
```

Mapping compliance harus versioned.

---

# 6. Target Users

## Security Engineer

Menjalankan assessment dan menganalisis vulnerability.

## Penetration Tester

Mengelola scope, testing session, evidence dan reporting.

## Application Security Engineer

Menangani SAST, SCA, secrets, DAST dan secure SDLC.

## Reverse Engineer

Menganalisis mobile, desktop, library, firmware dan binary.

## Developer

Melihat vulnerability yang relevan terhadap source code mereka.

## Tech Lead

Melihat security posture per application/team.

## DevOps / Platform Engineer

Menangani container, Kubernetes, CI/CD, IaC, server dan cloud.

## Cloud Security Engineer

Menganalisis cloud configuration dan IAM.

## Security Manager / CISO

Melihat organization risk.

## Auditor

Mengakses evidence, compliance mapping dan audit trail.

## Management

Melihat executive risk tanpa technical noise.

---

# 7. Tenant & Organization Model

Hierarchy:

```text
Organization
    │
    ├── Business Unit
    │
    ├── Team
    │
    ├── Workspace
    │
    └── Project
           │
           ├── Application
           ├── Repository
           ├── API
           ├── Domain
           ├── Mobile App
           ├── Cloud Account
           └── Infrastructure
```

Support:

```text
Multi Organization
Multi Tenant
Multiple Workspace
Multiple Environment
```

Environment:

```text
Development
QA
SIT
UAT
Staging
Production
DR
```

---

# 8. Asset Inventory

Setiap security assessment harus bermula dari asset.

Asset types:

```text
Domain
Subdomain
IP
Host
Service
Port
URL
Web Application
API
Repository
Package
Mobile Application
Desktop Application
Binary
Container Image
Kubernetes Cluster
Cloud Account
Database
Bucket
Queue
Topic
Serverless Function
VM
Certificate
Secret
CI/CD Pipeline
Git Repository
Docker Registry
Firmware
Device
AI Model
LLM Application
Vector Database
```

Asset mempunyai:

```text
Owner
Team
Environment
Business Unit
Criticality
Data Classification
Internet Exposure
Authentication Requirement
Technology
Dependencies
Tags
Location
Compliance Scope
Lifecycle
```

---

# 9. Asset Discovery

Platform harus melakukan asset discovery dari sumber yang telah diotorisasi.

Sources:

```text
GitHub
GitLab
Bitbucket

AWS
Azure
GCP

Kubernetes
Docker Registry

DNS
Certificate Inventory

CMDB

API Gateway

OpenAPI

Postman

CI/CD

Manual Import
CSV
API
```

Asset baru harus dapat dibandingkan dengan inventory sebelumnya.

Contoh:

```text
Yesterday
243 assets

Today
247 assets

New:
api-v3.company.com
admin-preview.company.com
payment-service
new Docker image
```

---

# 10. External Attack Surface Management

Platform menyediakan EASM.

Capabilities:

```text
Domain inventory
Subdomain discovery
Public service exposure
Certificate inventory
Technology fingerprint
Cloud exposure
Expired asset
Unknown asset
Shadow IT indicator
Forgotten staging environment
Misconfigured storage
External API inventory
```

Setiap asset diberi status:

```text
Managed
Unmanaged
Unknown
Approved
Deprecated
Shadow Asset
```

---

# 11. SAST Engine

Static Application Security Testing.

Languages target:

```text
Java
Kotlin
JavaScript
TypeScript
Python
Go
C#
C/C++
Swift
PHP
Ruby
Rust
Dart
Shell
SQL
```

Detection categories:

```text
Injection
Unsafe deserialization
Cryptography misuse
Authentication weakness
Authorization weakness
Sensitive data exposure
Path traversal
Command execution risk
Unsafe file handling
SSRF patterns
XXE
Race condition
Memory safety weakness
Logging weakness
Error handling
Hardcoded credentials
Insecure randomness
```

Finding harus menunjukkan:

```text
source
sink
data flow
affected function
file
line
call chain
confidence
security rule
recommendation
```

---

# 12. Software Composition Analysis

Analyze third-party dependency.

Support:

```text
Maven
Gradle
npm
pnpm
yarn
pip
Poetry
Go Modules
NuGet
Cargo
Composer
CocoaPods
Swift Package Manager
Flutter/Dart packages
```

Output:

```text
Component
Version
CVE
CVSS
EPSS
KEV
License
Fixed Version
Dependency Path
Direct / Transitive
Reachability
```

Example:

```text
application
   ↓
library A
   ↓
library B
   ↓
vulnerable library
```

Reachability analysis menjadi faktor utama risk calculation.

---

# 13. SBOM Management

Platform dapat:

```text
Generate SBOM
Import SBOM
Compare SBOM
Version SBOM
Search Components
Identify vulnerable components
```

Support standardized formats seperti:

```text
CycloneDX
SPDX
```

Setiap release dapat mempunyai immutable SBOM snapshot.

---

# 14. Secret Detection

Detect:

```text
API keys
Access token
Private key
Cloud credentials
Database credentials
JWT secret
OAuth client secret
Certificates
Webhook secrets
Firebase credentials
Signing material
```

Sumber scan:

```text
Current code
Git history
Commit
Branches
Container
Build artifact
Config file
Logs
IaC
```

Secret evidence harus otomatis dimasking.

Contoh:

```text
AKIA***********73K
```

Plain secret tidak boleh ditampilkan tanpa privileged access.

---

# 15. Web Application Security

DAST engine melakukan authorized runtime assessment.

Coverage:

```text
Authentication
Authorization
Input validation
Session
Cookies
Headers
CORS
CSP
TLS
Encryption
File handling
Redirect
Cache
Error handling
WebSocket
Business-flow controls
```

Support authenticated scan.

Authentication type:

```text
Username/Password
Bearer Token
API Key
OAuth2
OIDC
SAML
Custom Login
Cookie Session
```

Platform harus mendukung browser-based crawling.

---

# 16. API Security Platform

Support:

```text
REST
GraphQL
gRPC
WebSocket
SOAP
AsyncAPI
```

Import:

```text
OpenAPI
Swagger
Postman Collection
HAR
GraphQL Schema
AsyncAPI
```

Capabilities:

```text
Endpoint inventory
Parameter inventory
Authentication detection
Authorization analysis
Schema validation
Response analysis
Sensitive field discovery
Deprecated API detection
Version discovery
Unused endpoint
Shadow API
Zombie API
```

Risk mapping mengikuti OWASP API Security categories.

---

# 17. Mobile Security — Android

Input:

```text
APK
AAB
Source Code
Repository
```

Analysis layers:

```text
APK
Manifest
DEX
Resources
Assets
Native Libraries
Certificates
Network Configuration
Dependencies
Source
Runtime
```

Checks:

```text
Exported components
Permissions
Deep Links
Intent Filters
Backup configuration
Debug configuration
Cleartext traffic
Network Security Config
WebView
JavaScript bridge
Cryptography
Local storage
Database
SharedPreferences
DataStore
Keystore usage
Clipboard
Screenshots
Logging
Root detection
Anti-debug
Tamper protection
Certificate pinning
Obfuscation
Signing
Native code
Sensitive strings
API endpoints
Firebase configuration
```

Mapping terhadap MASVS/MASWE/MASTG.

---

# 18. Mobile Security — iOS

Input:

```text
IPA
Source
Repository
```

Analyze:

```text
Info.plist
Entitlements
Keychain usage
ATS
URL schemes
Universal links
Binary
Frameworks
Certificates
Local storage
Crypto
Network
Jailbreak detection
Anti-debug
Tamper protection
Sensitive strings
```

---

# 19. Reverse Engineering Workspace

Reverse engineering menjadi first-class module, bukan hanya utility.

Workspace:

```text
Artifact Overview

Strings
Symbols
Imports
Exports
Functions
Classes
Libraries
Resources
Certificates
Sections
Metadata
Endpoints
Crypto Indicators
Interesting Functions
Cross References
Call Graph
Control Flow
```

Supported artifact:

```text
APK
DEX
AAB
IPA
Mach-O
PE
DLL
EXE
ELF
SO
JAR
WASM
Firmware
```

Platform dapat mengintegrasikan engine seperti:

```text
JADX
APKTool
Ghidra
Rizin
MobSF
```

Dynamic instrumentation hanya dapat dijalankan dalam authorized isolated environment.

---

# 20. Binary Security

Analyze:

```text
Compiler protections
Debug symbols
Unsafe functions
Embedded secrets
Cryptographic implementation
Imported libraries
Signing
Packers
Obfuscation
Memory protection
Dependencies
Interesting strings
Network endpoints
```

Binary findings masuk ke Finding Engine yang sama.

---

# 21. Container Security

Analyze:

```text
Docker Image
Base Image
Packages
Libraries
Secrets
Malware indicator
Configuration
Permissions
User
Filesystem
Dockerfile
```

Detect:

```text
Critical CVE
Outdated packages
Root container
Embedded secret
Dangerous capability
Unnecessary package
Misconfiguration
```

---

# 22. Kubernetes Security

Analyze:

```text
Cluster
Namespace
Deployment
Pod
Service
Ingress
Secret
ConfigMap
RBAC
NetworkPolicy
ServiceAccount
Admission configuration
```

Security domains:

```text
RBAC
Privilege
Container isolation
Secrets
Network exposure
Image security
Pod configuration
Resource configuration
Control plane configuration
```

---

# 23. Infrastructure as Code Security

Support:

```text
Terraform
Helm
Kubernetes YAML
CloudFormation
Ansible
Dockerfile
```

Perform:

```text
Misconfiguration detection
Secret detection
Cloud policy validation
Compliance mapping
Security best-practice validation
```

---

# 24. Cloud Security

Cloud:

```text
AWS
Azure
GCP
```

Areas:

```text
IAM
Network
Storage
Compute
Database
Secrets
Encryption
Logging
Monitoring
Public exposure
Serverless
Container
Key management
```

Cloud inventory menjadi bagian dari unified asset graph.

---

# 25. Identity & IAM Security

Analyze:

```text
Users
Roles
Policies
Service Accounts
API identities
Machine identities
Permissions
Trust relationships
```

Detect:

```text
Excessive privileges
Unused privilege
Public trust
Wildcard permissions
Dormant identity
Long-lived credentials
Risky service account
Privilege chain
```

---

# 26. Network Vulnerability Assessment

Authorized infrastructure assessment:

```text
Host inventory
Port inventory
Service inventory
TLS
Certificate
Protocol
Version
Configuration
Known vulnerabilities
```

Network testing harus tunduk pada scope dan policy.

---

# 27. Database Security

Supported examples:

```text
PostgreSQL
MySQL
Oracle
SQL Server
MongoDB
Redis
Elasticsearch
```

Analyze:

```text
Exposure
Encryption
Authentication
Authorization
Default configuration
Version
Audit configuration
Risky privilege
Backup exposure
```

---

# 28. CI/CD Security

Platforms:

```text
GitHub Actions
GitLab CI
Jenkins
Azure DevOps
Bitbucket Pipeline
```

Analyze:

```text
Pipeline permissions
Secrets
Third-party actions
Build environment
Artifact integrity
Deployment controls
Branch protection
Approval controls
```

---

# 29. Software Supply Chain Security

Platform harus menghubungkan:

```text
Repository
   ↓
Dependency
   ↓
Build
   ↓
Artifact
   ↓
Container
   ↓
Registry
   ↓
Deployment
```

Capabilities:

```text
SBOM
Dependency risk
Artifact provenance
Signature verification
Build integrity
Package risk
Malicious package indicators
Typosquatting indicators
License risk
```

---

# 30. AI / LLM Security

Platform dirancang agar siap menguji AI-powered applications.

Asset:

```text
LLM Application
Model API
Prompt
Agent
Plugin
Tool
Vector Database
RAG
Dataset
Model
```

Security categories:

```text
Prompt boundary issues
Sensitive information exposure
Authorization around tools
Insecure output handling
Excessive agent privileges
RAG authorization
Data exposure
Model supply chain
Unsafe integration
Cost/resource abuse
```

AI testing harus fokus pada controlled security validation.

---

# 31. Browser Extension Security

Analyze:

```text
Manifest
Permissions
Content scripts
Background scripts
Storage
Messaging
Network
External communication
Web accessible resources
```

---

# 32. Firmware & IoT Security

Future enterprise module.

Analyze:

```text
Firmware image
Filesystem
Packages
Services
Certificates
Keys
Configuration
Native binaries
Network endpoints
Update mechanism
```

---

# 33. Threat Modeling

Project dapat membuat model:

```text
User
 ↓
Web
 ↓
API Gateway
 ↓
Service
 ↓
Database
```

Platform menyimpan:

```text
Component
Trust Boundary
Data Flow
Asset
Entry Point
Threat
Security Control
```

Threat model dapat menggunakan STRIDE-style categorization dan custom organizational controls.

---

# 34. Security Graph

Ini salah satu core differentiator.

Platform membentuk graph:

```text
Asset
Component
Repository
Dependency
API
Identity
Vulnerability
Secret
Cloud Resource
Network Service
Data
```

Contoh:

```text
Internet
   │
   ▼
api.company.com
   │
   ▼
API Gateway
   │
   ▼
payment-service
   │
   ├──── vulnerable dependency
   │
   ▼
Database
```

Dengan graph ini platform memahami **context**, bukan hanya vulnerability.

---

# 35. Attack Path Analysis

Correlation Engine dapat menunjukkan kemungkinan security exposure chain.

Contoh:

```text
Public Asset
    ↓
Weak Authentication
    ↓
Excessive Permission
    ↓
Backend Service
    ↓
Sensitive Data
```

Attack Path harus menunjukkan:

```text
Entry Point
Affected Assets
Security Weaknesses
Trust Relationships
Potential Impact
Existing Controls
Risk
Recommended Mitigation
```

Platform tidak perlu melakukan uncontrolled autonomous exploitation untuk membuktikan attack path.

---

# 36. Finding Normalization Engine

Semua scanner menghasilkan format berbeda.

Normalization Engine mengubah semuanya menjadi canonical finding.

Canonical Finding:

```json
{
  "findingId": "FND-001292",
  "title": "Broken Object Level Authorization",
  "type": "AUTHORIZATION",
  "severity": "HIGH",
  "confidence": "HIGH",
  "status": "OPEN",
  "asset": "customer-api",
  "environment": "production",
  "source": "api-security-engine",
  "cwe": ["CWE-639"],
  "owasp": ["API1:2023"],
  "cvss": 8.1,
  "epss": null,
  "internetExposed": true,
  "reachable": true,
  "businessCriticality": "CRITICAL",
  "owner": "Customer Platform Team"
}
```

---

# 37. Deduplication Engine

Finding dari:

```text
Semgrep
CodeQL
ZAP
Dependency Scanner
Cloud Scanner
Manual Pentest
```

tidak boleh otomatis menjadi lima vulnerability jika root cause-nya sama.

Deduplication mempertimbangkan:

```text
Asset
Location
CWE
Endpoint
Parameter
Dependency
Fingerprint
Data flow
Code path
Scanner
```

---

# 38. Finding Correlation

Contoh:

```text
SAST:
Potential unsafe authorization

+

DAST:
Unauthorized object access

+

API Inventory:
Endpoint internet exposed

+

Asset:
Contains confidential data
```

Correlation:

```text
Confirmed High-Risk Authorization Finding
```

---

# 39. Confidence Score

Setiap finding memiliki:

```text
Confirmed
High Confidence
Medium Confidence
Low Confidence
Informational
```

Confidence tidak sama dengan severity.

---

# 40. Unified Risk Engine

Severity saja tidak cukup.

Risk Engine mempertimbangkan:

```text
CVSS
EPSS
CISA KEV
Asset Criticality
Business Impact
Internet Exposure
Reachability
Exploit Prerequisite
Authentication Requirement
Data Sensitivity
Environment
Existing Security Controls
Finding Confidence
Exploit Evidence
Attack Path
Age
```

Conceptual:

```text
Technical Severity
        +
Threat Likelihood
        +
Asset Criticality
        +
Exposure
        +
Business Impact
        +
Reachability
        -
Compensating Controls
        =
Contextual Risk
```

Risk range:

```text
0–20   Low
21–40  Moderate
41–60  High
61–80  Very High
81–100 Critical
```

Organization dapat customize threshold.

---

# 41. Security Score

Platform dapat memberikan:

```text
Organization Score

74 / 100
```

Kemudian:

```text
Application Security       71
Mobile Security            81
API Security               64
Cloud Security             76
Infrastructure             84
Supply Chain               69
Identity Security          73
```

Security score harus transparent.

User dapat melihat alasan score turun.

---

# 42. Finding Lifecycle

Status:

```text
New
Triaging
Confirmed
Assigned
In Progress
Fixed
Ready for Retest
Retesting
Resolved
Risk Accepted
False Positive
Duplicate
Won't Fix
Reopened
```

Semua perubahan memiliki audit history.

---

# 43. Remediation Workflow

```text
Finding
   ↓
Triage
   ↓
Assign
   ↓
Developer Fix
   ↓
Commit / PR
   ↓
Rescan
   ↓
Retest
   ↓
Resolved
```

---

# 44. SLA Management

Example policy:

```text
Critical     24 hours
High          7 days
Medium       30 days
Low          90 days
```

Dashboard:

```text
Within SLA
Approaching SLA
SLA Breached
```

---

# 45. Risk Acceptance

Risk tidak boleh hanya di-close.

Risk acceptance mempunyai:

```text
Approver
Reason
Expiration
Compensating Control
Business Justification
Evidence
```

Expired acceptance otomatis kembali untuk review.

---

# 46. Retesting

User dapat memilih:

```text
Retest Finding
Retest Asset
Retest Scan
Retest Release
```

Report membandingkan:

```text
Before
After
```

---

# 47. Baseline & Delta Analysis

Setiap assessment disimpan sebagai snapshot.

Contoh:

```text
Release 1.8

Critical  5
High     21


Release 1.9

Critical  1
High     13
```

Platform menunjukkan:

```text
Fixed
New
Reopened
Unchanged
Regression
```

---

# 48. AI Security Analyst

AI menjadi reasoning layer di atas evidence.

AI tidak menggantikan scanner.

Flow:

```text
Scanner
   ↓
Evidence
   ↓
Correlation
   ↓
AI Analysis
```

AI dapat:

```text
Explain finding
Explain root cause
Summarize evidence
Analyze code context
Explain data flow
Propose remediation
Generate secure-code recommendation
Compare alternative fix
Analyze architecture
Prioritize findings
Detect likely duplicate
Suggest likely false positive
Generate executive summary
Generate developer summary
Create remediation plan
Explain attack path
Generate report
```

---

# 49. AI Repository Understanding

AI membangun context:

```text
Repository
   ↓
Modules
   ↓
Classes
   ↓
Functions
   ↓
API
   ↓
Database
```

Sehingga vulnerability tidak dianalisis sebagai satu line code saja.

---

# 50. AI Root Cause Analysis

Contoh:

```text
Finding:
Authorization weakness

Endpoint:
GET /accounts/{id}

Controller
 ↓
Service
 ↓
Repository
```

AI dapat menunjukkan:

```text
Authentication is present.

However account ownership is not
validated before repository access.

Root Cause:
Object-level authorization missing
in AccountService.
```

---

# 51. AI Fix Assistant

Output:

```text
What is wrong

Why it matters

Recommended design change

Affected components

Suggested implementation approach

Recommended test

Potential regression risk
```

Developer tetap melakukan review.

---

# 52. Scanner Orchestrator

Platform tidak harus membuat semua security engine dari nol.

Architecture:

```text
                     Scan Orchestrator
                            │
                          Kafka
                            │
 ┌──────────────┬───────────┼───────────────┬─────────────┐
 ▼              ▼           ▼               ▼             ▼
SAST          SCA         DAST            Mobile        Cloud
Worker        Worker      Worker          Worker        Worker
```

Scanner worker dibuat isolated.

---

# 53. Scanner Plugin Architecture

Scanner harus plug-and-play.

Interface:

```text
Scanner Plugin
 ├── Metadata
 ├── Capabilities
 ├── Input
 ├── Execution
 ├── Output Parser
 └── Health Check
```

Dengan konsep ini organisasi dapat menambahkan scanner sendiri.

---

# 54. Potential Scanner Integrations

Contoh ecosystem:

```text
Semgrep
CodeQL
Trivy
Grype
Syft
OWASP ZAP
MobSF
JADX
APKTool
Ghidra
Rizin
Checkov
Kube-bench
Kube-hunter-style defensive checks
Gitleaks
TruffleHog
Nuclei templates in authorized policy-controlled mode
```

Tool merupakan execution engine.

Platform sendiri tetap memiliki:

```text
Asset Model
Orchestration
Normalization
Correlation
Risk
Workflow
Reporting
AI
```

---

# 55. Scan Profiles

## Passive

Tidak mengubah target.

## Quick

Security baseline cepat.

## Standard

Normal security assessment.

## Deep

Extended analysis dengan cakupan lebih besar.

## Release Gate

Security check sebelum deployment.

## Continuous

Berjalan saat ada perubahan.

## Compliance

Assessment berdasarkan control tertentu.

## Pentest Workspace

Manual + automated evidence collection.

---

# 56. Scope Management

Setiap active assessment harus mempunyai scope.

Example:

```text
Allowed

api-staging.company.com
10.1.20.0/24
Android APK build 341
repository/payment-service

Denied

production.company.com
third-party.com
```

Scope dapat memiliki:

```text
Allowed targets
Excluded paths
Allowed hours
Traffic limits
Environment
Approval
Expiration
```

---

# 57. Target Ownership Verification

Sebelum active external scan:

```text
DNS TXT
File Verification
Cloud Ownership
Repository Connection
Manual Organization Approval
```

Tujuannya mencegah penggunaan platform untuk unauthorized scanning.

---

# 58. Execution Safety

Scan worker harus mempunyai:

```text
Network policy
CPU limit
Memory limit
Timeout
Rate limit
Disk quota
Sandbox
Restricted credentials
Audit logging
```

Aggressive test profile membutuhkan higher authorization.

---

# 59. Pentest Engagement Management

Platform juga menjadi pentest workspace.

Engagement:

```text
Client
Project
Scope
Rules of Engagement
Test Window
Tester
Environment
Assets
Findings
Evidence
Report
Retest
```

---

# 60. Manual Finding

Pentester dapat membuat finding manual.

Fields:

```text
Title
Description
Severity
Risk
Affected Asset
Endpoint
Evidence
Impact
Root Cause
Recommendation
References
Screenshots
Attachments
```

Manual finding dan automated finding berada dalam workflow yang sama.

---

# 61. Evidence Management

Evidence type:

```text
Screenshot
HTTP Request
HTTP Response
Log
File
Code Snippet
Stack Trace
Scanner Result
Video
Artifact
Configuration
```

Evidence mempunyai:

```text
Timestamp
Author
Hash
Finding
Asset
Assessment
```

Sensitive evidence terenkripsi.

---

# 62. Evidence Integrity

Untuk audit-sensitive engagement:

```text
SHA-256
Timestamp
Immutable Evidence ID
Chain of Custody
Uploader
Collection Source
```

---

# 63. Reporting Engine

Reporting adalah core feature, bukan afterthought.

Platform menghasilkan beberapa report.

---

# 64. Executive Report

Untuk:

```text
CEO
CTO
CISO
Director
Client Management
```

Isi:

```text
Executive Summary
Overall Security Score
Risk Distribution
Critical Business Risk
Attack Surface
Top Security Concerns
Trend
Business Impact
Remediation Progress
Recommendations
```

Tidak terlalu technical.

---

# 65. Technical Security Report

Isi:

```text
Scope
Methodology
Architecture
Testing Coverage
Findings
Evidence
Severity
Risk
Affected Components
Root Cause
Technical Impact
Business Impact
Remediation
References
Retest Status
```

---

# 66. Developer Report

Fokus:

```text
Repository
File
Line
Function
Root Cause
Code Path
Fix Recommendation
Secure Alternative
Test Recommendation
```

---

# 67. Pentest Report

```text
Engagement Information
Scope
Rules of Engagement
Methodology
Executive Summary
Technical Findings
Evidence
Risk
Recommendations
Appendix
```

---

# 68. Retest Report

```text
Original Finding
Original Severity
Original Evidence

Fix

Retest Evidence

Result:
PASS / FAIL / PARTIAL
```

---

# 69. Compliance Report

Contoh:

```text
OWASP ASVS

Total Controls     286
Passed             218
Failed              34
Not Applicable      21
Not Tested          13
```

Setiap control dapat terhubung ke evidence.

---

# 70. Attack Surface Report

Isi:

```text
Domains
Subdomains
Public Hosts
Services
Certificates
Cloud Assets
External APIs
Unknown Assets
Exposure Changes
```

---

# 71. Software Supply Chain Report

Isi:

```text
SBOM Summary
Critical Dependencies
Known Exploited Vulnerabilities
Licensing
Outdated Packages
Dependency Risk
Artifact Integrity
```

---

# 72. Security Posture Report

Per:

```text
Application
Team
Business Unit
Organization
```

Trend:

```text
Risk
Security Score
MTTR
SLA
Finding Count
Regression
Coverage
```

---

# 73. Report Export

Formats:

```text
PDF
HTML
JSON
CSV
SARIF
API
```

Enterprise:

```text
Custom Template
Company Logo
White Label
Customer Branding
Digital Signature
```

---

# 74. Security Dashboard

Landing dashboard:

```text
Security Score

Critical Risk
High Risk

Internet Exposed Assets

Known Exploited Vulnerabilities

SLA Breach

Top Risk Applications

Attack Paths

Security Trend

New Findings

Remediation Progress
```

---

# 75. Application Dashboard

Example:

```text
Mobile Banking

Security Score
72

Critical   2
High       9
Medium    31
Low       41

Repositories      8
APIs             74
Mobile Apps       2
Cloud Resources 137
Containers       28
```

---

# 76. Vulnerability Explorer

Filters:

```text
Severity
Risk
CVE
CWE
OWASP
Asset
Application
Owner
Scanner
Environment
Status
SLA
KEV
EPSS
Internet Exposure
Reachability
```

---

# 77. Attack Graph UI

Interactive visualization:

```text
Internet
   ↓
Web
   ↓
API
   ↓
Service
   ↓
Database
```

Click setiap node untuk melihat:

```text
Asset
Exposure
Finding
Risk
Owner
Controls
```

---

# 78. Reverse Engineering UI

Sections:

```text
Overview
Manifest
Strings
Classes
Libraries
Functions
Endpoints
Crypto
Certificates
Security Controls
Call Graph
Files
Findings
```

---

# 79. Scan Center

Display:

```text
Queued
Running
Completed
Failed
Cancelled
```

Details:

```text
Scanner
Worker
Duration
Asset
Profile
Progress
Logs
Findings
```

---

# 80. Remediation Center

Views:

```text
By Team
By Application
By SLA
By Severity
By Risk
By Sprint
```

---

# 81. Integration Center

SCM:

```text
GitHub
GitLab
Bitbucket
Azure Repos
```

CI/CD:

```text
Jenkins
GitHub Actions
GitLab CI
Azure DevOps
```

Issue Tracker:

```text
Jira
GitHub Issues
GitLab Issues
Azure Boards
```

Communication:

```text
Slack
Microsoft Teams
Email
Webhook
```

SIEM:

```text
Splunk
Elastic
Microsoft Sentinel
```

Cloud:

```text
AWS
Azure
GCP
```

---

# 82. Security Gate

CI/CD policy example:

```text
PR Security Gate

Critical     0 allowed
High         0 new
Medium       <= 5 new
Secret       0
KEV          0
```

Result:

```text
PASS

or

BLOCKED
```

---

# 83. Pull Request Security Review

PR:

```text
12 files changed

New findings:

Critical 0
High     1
Medium   2

Risk:
BLOCK
```

Comment dapat menunjukkan relevant finding tanpa membanjiri PR.

---

# 84. Incremental Scanning

Tidak semua commit membutuhkan full scan.

Platform memahami:

```text
Changed Files
Changed Dependencies
Changed APIs
Changed Containers
```

dan hanya menjalankan scanner yang relevan.

---

# 85. Event-Driven Security

Trigger:

```text
Git Push
Pull Request
Merge
Build
Deployment
New Container
New CVE
EPSS change
KEV addition
New Cloud Resource
New Public Asset
Certificate change
```

---

# 86. Continuous Vulnerability Re-evaluation

Finding lama dapat berubah risk tanpa code berubah.

Contoh:

```text
Yesterday

CVE Risk
Medium


Today

CISA KEV
YES

EPSS increased
```

Platform otomatis menaikkan priority.

---

# 87. Security Intelligence

Enrichment:

```text
CVE
CWE
CVSS
EPSS
KEV
Vendor Advisory
Affected Version
Fixed Version
Exploit Status
References
```

---

# 88. False Positive Management

Finding dapat ditandai false positive.

Namun suppression membutuhkan:

```text
Reason
Approver
Expiration
Scope
```

Suppression tidak boleh menghapus historical evidence.

---

# 89. Vulnerability Regression

Jika finding sudah fixed lalu muncul lagi:

```text
REOPENED
```

Platform harus menunjukkan:

```text
Previously fixed
Fixed commit
Reintroduced commit
Current owner
```

---

# 90. Security Ownership

Mapping:

```text
Repository
   ↓
Team
   ↓
Tech Lead
   ↓
Security Champion
```

Finding otomatis diassign.

Support:

```text
CODEOWNERS
Custom ownership
CMDB
Repository metadata
```

---

# 91. Developer Experience

Developer seharusnya tidak perlu menjadi pentester untuk memperbaiki vulnerability.

Finding harus menjawab:

```text
What happened?
Where?
Why?
How dangerous?
How to fix?
How to verify?
```

---

# 92. Notifications

Events:

```text
Critical Finding
KEV Match
SLA approaching
SLA breached
Security Score drop
New attack path
Retest failed
Scan failed
Risk acceptance expired
```

---

# 93. Role Based Access Control

Roles:

```text
Organization Owner
Security Admin
Security Engineer
Pentester
Developer
Tech Lead
Auditor
Viewer
Client
```

Fine-grained permissions.

---

# 94. Attribute Based Access

Enterprise implementation dapat menambahkan ABAC:

```text
Team
Business Unit
Project
Environment
Classification
Region
```

---

# 95. Authentication

Support:

```text
Password
MFA
Passkey
SSO
SAML
OIDC
LDAP
SCIM provisioning
```

---

# 96. Audit Logging

Audit:

```text
Login
Finding viewed
Evidence downloaded
Finding modified
Risk accepted
Scan created
Target added
Permission changed
Report generated
Secret accessed
```

Audit log harus immutable atau tamper-evident.

---

# 97. Sensitive Data Handling

Security platform akan menyimpan sangat sensitive information.

Required:

```text
Encryption at rest
TLS
Field-level encryption
Secrets manager
Key rotation
Tenant isolation
Data masking
Access logging
Retention
Secure deletion
```

---

# 98. Scanner Isolation

Setiap scanner worker:

```text
Ephemeral
Sandboxed
Network restricted
Resource limited
Authenticated
Signed image
Monitored
```

Deep binary/reverse-engineering workloads dapat menggunakan stronger isolation seperti VM/microVM workers.

---

# 99. High-Level Technical Architecture

Recommended:

```text
                         React Web
                            │
                     API Gateway
                            │
                 Spring Boot Platform
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
    PostgreSQL            Redis             Object Storage
       │
       ▼
 Scan Orchestrator
       │
     Kafka
       │
 ┌─────┼──────┬──────┬──────┬───────┬───────┐
 ▼     ▼      ▼      ▼      ▼       ▼       ▼
SAST  SCA   DAST   Mobile  Cloud  Network   RE
       │
       ▼
 Finding Normalizer
       │
       ▼
 Deduplication
       │
       ▼
 Correlation Engine
       │
       ▼
 Security Graph
       │
       ▼
 Risk Engine
       │
       ▼
 AI Security Analyst
       │
       ▼
 Remediation / Reporting
```

---

# 100. Recommended Core Stack

Frontend:

```text
React
TypeScript
Tailwind
TanStack Query
```

Backend:

```text
Java
Spring Boot
Spring Security
Spring Modulith initially
```

Messaging:

```text
Kafka
```

Primary DB:

```text
PostgreSQL
```

Cache:

```text
Redis
```

Object Storage:

```text
S3 / MinIO
```

Search:

```text
OpenSearch / Elasticsearch
```

Graph:

Start with PostgreSQL relationship model.

Move/selectively add graph database when attack-graph complexity requires it.

Execution:

```text
Docker
Kubernetes
```

Observability:

```text
OpenTelemetry
Prometheus
Grafana
Loki
```

Secrets:

```text
Vault / Cloud KMS
```

---

# 101. Architecture Strategy

Jangan langsung membangun 40 microservices.

Initial architecture:

```text
Modular Monolith
+
Independent Scanner Workers
+
Kafka
```

Domains dalam backend:

```text
Identity
Organization
Asset
Project
Scan
Finding
Risk
Security Graph
Remediation
Reporting
Integration
Audit
```

Scanner worker tetap independen karena workload-nya tidak trusted dan resource intensive.

---

# 102. Core Data Entities

Main entities:

```text
Organization
User
Team
Workspace
Project
Application
Asset
AssetRelationship
Repository
Component
SBOM
Scan
ScanJob
Scanner
Finding
FindingInstance
Evidence
Vulnerability
Risk
AttackPath
SecurityControl
ComplianceRequirement
Remediation
Retest
Report
Integration
AuditEvent
```

---

# 103. Finding vs Finding Instance

Penting untuk desain data.

Example:

```text
Finding

CVE-XXXX
in log4j
```

dapat memiliki:

```text
Instance 1
payment-service

Instance 2
customer-service

Instance 3
report-service
```

Sehingga platform tidak menghitung satu vulnerability berkali-kali tanpa context.

---

# 104. Security Knowledge Graph

Relationships:

```text
APPLICATION USES REPOSITORY

REPOSITORY BUILDS ARTIFACT

ARTIFACT CONTAINS COMPONENT

COMPONENT HAS VULNERABILITY

APPLICATION EXPOSES API

API CALLS SERVICE

SERVICE CONNECTS DATABASE

IDENTITY CAN_ACCESS RESOURCE
```

Ini fondasi attack-path analysis.

---

# 105. API First

Semua fungsi utama platform memiliki API.

Example domains:

```text
/api/v1/assets
/api/v1/scans
/api/v1/findings
/api/v1/risks
/api/v1/reports
/api/v1/projects
/api/v1/integrations
```

Dengan API-first architecture, customer dapat membuat automation sendiri.

---

# 106. Webhook

Events:

```text
finding.created
finding.updated
finding.resolved

scan.started
scan.completed

risk.changed

asset.discovered

report.generated
```

---

# 107. Performance Requirements

Target initial enterprise:

```text
100k+ assets
1M+ findings
10M+ finding instances
thousands of repositories
parallel scan workers
```

Heavy scan workloads tidak dijalankan di API nodes.

---

# 108. Availability

Target SaaS enterprise:

```text
99.9%+
```

Security scan worker failure tidak boleh menyebabkan platform API down.

---

# 109. Horizontal Scaling

Scale independently:

```text
API
Scanner
Normalizer
Risk Worker
AI Worker
Reporting
```

---

# 110. Observability

Setiap scan memiliki distributed trace:

```text
Request
 ↓
Scan
 ↓
Job
 ↓
Worker
 ↓
Scanner
 ↓
Parser
 ↓
Finding
```

Metrics:

```text
Queue depth
Scan duration
Worker failure
Finding throughput
CPU
Memory
Scanner availability
```

---

# 111. Disaster Recovery

Required:

```text
Database Backup
Object Storage Backup
Configuration Backup
Key Recovery Procedure
Cross-region strategy
```

---

# 112. Product Security

Platform itu sendiri harus memiliki very high security baseline.

Required:

```text
Secure SDLC
Threat Modeling
SAST
SCA
DAST
Secret Detection
Container Security
Dependency Review
Infrastructure Security
Pentest
Audit
MFA
SSO
RBAC
```

Idealnya platform memakan dog-food sendiri:

> Security Platform scans Security Platform.

---

# 113. Data Residency

Enterprise dapat menentukan:

```text
Indonesia
Australia
Singapore
EU
US
Private Data Center
```

depending deployment model.

---

# 114. Deployment Models

## SaaS

Platform dan workers berada di cloud provider.

## Hybrid

Control plane SaaS.

Scanner worker berada di network customer.

```text
Cloud Control Plane
        │
        ▼
Customer Scan Agent
        │
        ▼
Internal Target
```

## Full On-Premise

Seluruh platform berada di infrastructure customer.

Sangat penting untuk bank dan regulated organizations.

---

# 115. Private Scanner Agent

Agent digunakan untuk scanning:

```text
Internal API
Private Repository
Internal Network
Private Kubernetes
Database
```

Agent membuat outbound connection sehingga organisasi tidak harus membuka inbound port.

---

# 116. Report Access

Report mempunyai classification:

```text
Public
Internal
Confidential
Restricted
```

Download dapat:

```text
Require MFA
Expire
Watermark
Audit
```

---

# 117. Search

Global search:

```text
CVE-2026-xxxx

api.company.com

CWE-89

payment-service

log4j
```

Search results menghubungkan seluruh asset dan findings.

---

# 118. Security Command Center

Enterprise homepage:

```text
Organization Security Posture

Risk Score
Attack Surface
Critical Assets
Critical Vulnerabilities
KEV
Attack Paths
SLA
Security Coverage
Remediation Velocity
Trend
```

---

# 119. Security Coverage

Platform tidak hanya mengatakan aplikasi aman.

Platform menunjukkan:

```text
SAST              ✓
SCA               ✓
Secrets           ✓
DAST              ✓
API               ✓
Mobile            ✕
Infrastructure    ✓
Cloud             Partial
Threat Model      ✕
```

Dengan begitu management tahu apa yang **belum diuji**.

---

# 120. Confidence & Coverage

Report harus membedakan:

```text
No vulnerability detected
```

dan

```text
Not tested
```

Ini sangat penting.

Tidak ada finding ≠ aman.

---

# 121. Product Metrics

Track:

```text
Mean Time to Detect
Mean Time to Remediate
Critical Exposure Time
SLA Compliance
Security Score
Risk Reduction
Reopened Findings
Vulnerability Recurrence
False Positive Rate
Coverage
Assets Without Owner
Internet-exposed Critical Assets
```

---

# 122. AI Metrics

Measure:

```text
AI remediation acceptance
AI false-positive recommendation accuracy
Duplicate detection accuracy
Analyst time saved
Report editing required
```

---

# 123. UX Principle

Security platform biasanya gagal karena terlalu banyak information.

Platform menggunakan progressive disclosure.

Dashboard:

```text
Risk
```

Finding page:

```text
Problem
Impact
Evidence
Fix
```

Advanced tab:

```text
Raw scanner
Technical metadata
Correlation
Trace
```

---

# 124. Scan Creation UX

Wizard:

```text
1. Select Project
2. Select Asset
3. Verify Authorization
4. Select Scan Profile
5. Authentication
6. Schedule
7. Review
8. Run
```

---

# 125. Scheduled Scan

Schedule:

```text
Hourly
Daily
Weekly
Monthly
Release
Custom
```

---

# 126. Security Campaign

Organization dapat membuat:

```text
Log4Shell Remediation Campaign

Affected Assets    47
Resolved           39
Remaining           8
```

atau:

```text
Remove Public S3 Exposure

Affected 12
Resolved 10
```

---

# 127. Organization Policies

Policy examples:

```text
No Critical vulnerability in production

No KEV in internet-facing assets

No exposed secrets

All production applications require SBOM

All Critical findings fixed within 24 hours

All mobile banking applications require MASVS assessment
```

---

# 128. Exceptions

Policy exception membutuhkan:

```text
Reason
Owner
Approver
Expiration
Compensating Control
```

---

# 129. Compliance Control Center

Framework:

```text
Framework
 ↓
Control
 ↓
Technical Requirement
 ↓
Security Test
 ↓
Evidence
 ↓
Finding
```

Dengan demikian compliance tidak hanya menjadi checklist manual.

---

# 130. Custom Security Framework

Enterprise dapat membuat:

```text
Bank Security Standard
Company Secure Coding Standard
Fintech Mobile Standard
```

dan mapping ke ASVS/MASVS/CWE.

---

# 131. Report Templates

Template library:

```text
Executive Security Assessment
Web Pentest
API Pentest
Android Assessment
iOS Assessment
Cloud Assessment
Infrastructure VA
Source Code Review
Secure Code Review
Compliance Assessment
Full Application Security Assessment
Retest
```

---

# 132. White Label

Consulting company dapat:

```text
Custom brand
Logo
Domain
Report
Email template
Client portal
```

---

# 133. Client Portal

Pentest provider dapat memberikan client access.

Customer dapat:

```text
View findings
Comment
Upload evidence
Submit fix
Request retest
Download report
```

---

# 134. Collaboration

Finding discussion:

```text
Security Engineer
Developer
Tech Lead
Client
```

Dengan:

```text
Comment
Mention
Attachment
Status change
Activity timeline
```

---

# 135. Ticket Synchronization

Finding dapat sync ke Jira.

```text
Security Platform
      ↕
Jira
```

Status dapat dua arah.

---

# 136. Ultimate Product Positioning

Platform bukan hanya:

```text
Vulnerability Scanner
```

Tetapi:

```text
Unified Security Engineering Platform
```

yang menggabungkan:

```text
Application Security
DevSecOps
Vulnerability Management
Attack Surface Management
Mobile Security
Reverse Engineering
Cloud Security
Infrastructure Security
Supply Chain Security
Pentest Management
Security Posture Management
Compliance
Risk Intelligence
AI Security Analysis
```

---

# 137. Primary Competitive Differentiators

## Unified Asset Graph

Semua security data terhubung.

## Cross-Scanner Correlation

Tidak hanya kumpulan alert.

## Full SDLC

```text
Code
 ↓
Build
 ↓
Artifact
 ↓
Deploy
 ↓
Runtime
 ↓
Remediation
```

## Mobile + Reverse Engineering Native

Bukan fitur tambahan.

## Contextual Risk

CVSS saja tidak menentukan priority.

## AI Reasoning Layer

AI memahami evidence dan architecture.

## Excellent Reporting

Report dibuat langsung dari security graph.

## Hybrid Deployment

Dapat digunakan enterprise regulated.

## Extensible Scanner Ecosystem

Tidak terikat satu engine.

---

# 138. Recommended Product Editions

## Community

Basic security scanning.

## Developer

Repository security + CI/CD.

## Professional

Application + API + mobile.

## Enterprise

Full platform.

## MSSP / Consultant

Multi-client security assessment dan white-label reporting.

---

# 139. Development Roadmap

## Phase 1 — Platform Foundation

Build:

```text
Authentication
Organization
Workspace
Project
Asset
Repository Integration
Scan Orchestrator
Finding
Evidence
Risk
Dashboard
Reporting
Audit
```

---

## Phase 2 — Application Security Core

```text
SAST
SCA
Secret Scan
SBOM
IaC
Container
CI/CD
```

---

## Phase 3 — Web & API

```text
Web Asset
Crawler
DAST
API Inventory
API Security
Authentication Profile
```

---

## Phase 4 — Mobile & Reverse Engineering

```text
APK/AAB
Android
IPA
iOS
Binary
JADX
APKTool
MobSF
Ghidra-style integration
Reverse Engineering Workspace
MASVS
```

---

## Phase 5 — Infrastructure

```text
Network
Server
Database
TLS
Cloud
Kubernetes
IAM
```

---

## Phase 6 — Security Intelligence

```text
CVSS
EPSS
KEV
CVE enrichment
Asset criticality
Contextual Risk
```

---

## Phase 7 — Security Graph

```text
Asset relationships
Dependency graph
Identity relationships
Attack paths
Blast radius
```

---

## Phase 8 — AI Security Analyst

```text
Finding explanation
Root cause analysis
Code understanding
Fix recommendation
Correlation
Prioritization
Report generation
```

---

## Phase 9 — Enterprise

```text
SSO
SCIM
Advanced RBAC
ABAC
Private Scanner
Hybrid
On-prem
Compliance
Custom framework
White label
Client portal
```

---

## Phase 10 — Advanced Security

```text
Firmware
IoT
AI/LLM security
Advanced binary analysis
Continuous Attack Surface
Purple-team validation
Custom scanner SDK
Security marketplace
```

---

# 140. MVP Recommendation

Walaupun ultimate PRD sangat luas, MVP sebaiknya jangan membangun semuanya sekaligus.

MVP paling kuat:

```text
PROJECT MANAGEMENT

+

ASSET INVENTORY

+

SOURCE CODE
SAST
SCA
Secrets

+

BACKEND/API
API Inventory
DAST

+

ANDROID
APK Analysis
MASVS
Reverse Engineering

+

FINDING MANAGEMENT

+

RISK ENGINE

+

AI ANALYST

+

REPORTING
```

Ini sudah dapat menjadi produk yang sangat berbeda karena menggabungkan:

```text
Source + Backend + API + Android
```

dalam satu security context.

---

# 141. MVP User Journey

```text
Create Organization
        ↓
Create Project
        ↓
Connect GitHub
        ↓
Upload APK
        ↓
Import OpenAPI
        ↓
Register staging domain
        ↓
Verify ownership
        ↓
Run Assessment
        ↓
SAST
SCA
Secrets
API
DAST
Android
        ↓
Normalize Findings
        ↓
Correlate
        ↓
Calculate Risk
        ↓
AI Analysis
        ↓
Security Dashboard
        ↓
Assign Remediation
        ↓
Developer Fix
        ↓
Retest
        ↓
Generate Report
```

---

# 142. Example Final Assessment

Project:

```text
Digital Banking
```

Assets:

```text
Android          1
Backend         14
Repositories    18
APIs           148
Containers      31
Cloud Assets   214
```

Results:

```text
Security Score

67 / 100


CRITICAL    3
HIGH       17
MEDIUM     42
LOW        71
INFO      103
```

Priority:

```text
1.

Authorization weakness

Risk
94 / 100

Asset
Payment API

Internet Exposure
YES

Asset Criticality
CRITICAL

Authentication
YES

Reachable
YES


2.

Vulnerable Dependency

Risk
91 / 100

CVSS
9.8

EPSS
High

Known Exploited
YES

Environment
Production


3.

Hardcoded Secret

Risk
88

Source
Android APK

Linked Service
Payment Backend
```

---

# 143. Application Relationship

Security Graph may identify:

```text
Android App
     │
     ├── calls
     ▼
Payment API
     │
     ├── authenticates through
     ▼
Identity Service
     │
     ├── accesses
     ▼
Payment Service
     │
     ├── writes
     ▼
Transaction Database
```

Security team tidak lagi melihat lima sistem yang terpisah.

Mereka melihat:

> **satu application ecosystem.**

---

# 144. Ultimate Goal

Platform harus mampu melihat perjalanan lengkap sebuah software:

```text
DESIGN
  ↓
CODE
  ↓
DEPENDENCY
  ↓
BUILD
  ↓
ARTIFACT
  ↓
CONTAINER
  ↓
CLOUD
  ↓
DEPLOYMENT
  ↓
NETWORK
  ↓
APPLICATION
  ↓
API
  ↓
USER
```

dan menjawab:

```text
WHAT IS VULNERABLE?

WHY?

WHERE?

HOW IMPORTANT?

WHAT CAN IT AFFECT?

WHO OWNS IT?

HOW DO WE FIX IT?

HAS IT BEEN FIXED?

CAN IT RETURN?

WHAT IS THE ORGANIZATION'S CURRENT RISK?
```

Itulah core vision produk.

---

# 145. Product Definition

Nama kategori produk yang paling tepat bukan:

> Vulnerability Scanner

dan bukan pula hanya:

> Pentest Platform.

Definisi yang lebih tepat:

> **Unified Security Engineering, Assessment & Risk Intelligence Platform**

atau:

> **Security Operating Platform**

yang menghubungkan:

```text
Discover
    ↓
Assess
    ↓
Analyze
    ↓
Correlate
    ↓
Prioritize
    ↓
Remediate
    ↓
Verify
    ↓
Monitor
    ↓
Report
```

menjadi satu continuous security lifecycle.
