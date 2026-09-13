# VulneraX - Code Reality Analysis

Analisis jujur berdasarkan **apa yang benar-benar ada di kode**, bukan yang tertulis di dokumentasi.

---

## Scorecard: Kode vs Dokumentasi

| Area | Rating | Kondisi Sebenarnya |
|------|:------:|-------------------|
| **Tenant Isolation** | 1/10 | Parameter diterima tapi **tidak dipakai** di query kritis |
| **MFA** | 3/10 | Secret generation real; verification **terima angka 6-digit apapun** |
| **OneClickService** | 6/10 | Orkestrasi + monitoring real; **tidak ada inteligensi** dalam pemilihan scanner |
| **Scanner Plugins** | 2/10 | **Tidak ada plugin interface**; analyzer hardcoded; "plugins" hanya string label |
| **Coverage Registry** | 0/10 | Module **tidak ada** di kode meski didokumentasikan |
| **Finding Correlation** | 1/10 | "Same asset + same type" dengan attack path string hardcoded |
| **Risk Engine** | 7/10 | Multi-factor scoring real dengan weights reasonable; belum production-calibrated |
| **Evidence Collection** | 1/10 | Placeholder text + random UUID sebagai sha256 |
| **Graph / Attack Path** | 3/10 | Nodes/edges dari data real; **connections synthetic**; attack path template hardcoded |
| **Dashboard** | 5/10 | Core metrics real tapi **load seluruh DB ke memory**; hardcoded asset counts |
| **Reporting** | 2/10 | JSON blob di DB + fake S3 path; **tidak ada PDF/HTML** |
| **Testing** | 2/10 | 44 file test, tapi ~35 hanya smoke test boilerplate |

---

## 1. Tenant Isolation — 1/10

### Apa yang ada di kode:

**Finding.java:**
- Entity punya `projectId` dan `assetId` tapi **TIDAK ADA field `organizationId`**

**FindingRepository.java:**
- Query: `findByProjectId`, `findByAssetId`, `findAll`
- **TIDAK ADA** method `findByOrganizationId`

**FindingService.java:**
```java
public Page<Finding> list(UUID projectId, UUID assetId, ...) {
    if (projectId != null) return findingRepo.findByProjectId(projectId, p);
    if (assetId != null) return findingRepo.findByAssetId(assetId, p);
    return findingRepo.findAll(p);  // <-- SEMUA data tanpa filter org
}
```

**DashboardService.java:**
```java
long totalAssets = orgId != null ? assetRepo.count() : assetRepo.count();
// ^^^ KEDUA SISI SAMA — orgId diabaikan total
```

**OrganizationService.java:**
```java
public Page<Workspace> listWorkspaces(UUID orgId, Pageable p) {
    return wsRepo.findAll(p);  // <-- orgId tidak dipakai
}
```

### Kesimpulan:
Organisasi-level multi-tenancy ada sebagai **konsep data model** (entity Organization/Workspace/Project), tapi **query-level isolation TIDAK di-enforce**. User mana saja bisa melihat semua data.

### Yang perlu diperbaiki:
- Tambah `organizationId` ke Finding, Scan, Asset
- Buat `@Filter` atau `@Where` JPA untuk auto-filter by org
- Atau gunakan Row-Level Security (RLS) di PostgreSQL
- Semua query harus pass `organizationId` dari JWT claims

---

## 2. MFA — 3/10

### Apa yang ada di kode:

**MfaController.java — Setup (REAL):**
```java
// Generate TOTP secret — CRYPTOGRAPHICALLY SOUND
java.security.SecureRandom sr = new java.security.SecureRandom();
byte[] bytes = new byte[20];
sr.nextBytes(bytes);
// ... Base32 encoding ... result: 160-bit secret
user.setMfaSecret(secret);
user.setMfaEnabled(true);
// otpauth:// URI + QR code URL — BAGUS
```

**MfaController.java — Verify (FAKE):**
```java
boolean ok = code != null && code.matches("\\d{6}");
return ApiResponse.ok(Map.of(
    "verified", ok,
    "message", ok ? "MFA verified" : "Invalid code (demo accepts any 6 digits)"
));
```

### Kesimpulan:
- Secret generation: **Real dan secure**
- TOTP validation: **100% dummy** — terima angka 6-digit apapun
- Secret yang di-store **tidak pernah dibaca** saat verifikasi

### Yang perlu diperbaiki:
- Implement TOTP HMAC-SHA1 computation (RFC 6238)
- Time-window validation (±30 detik)
- Recovery codes (8-10 backup codes)
- Enrollment lifecycle (setup → verify → enable)
- Rate limiting on verify attempts

---

## 3. OneClickService — 6/10

### Apa yang ada di kode:

**Target Detection (REAL):**
```java
private String detectType(String target) {
    if (target.matches(".*\\.(apk|ipa|aab)$")) return "MOBILE";
    if (target.matches(".*\\.(zip|tar|gz)$")) return "REPOSITORY";
    if (target.startsWith("http")) return detectWebType(target);
    // ... more detection
}
```

**Scanner Selection (NO INTELLIGENCE):**
```java
private List<String> scannersFor(String targetType) {
    return List.of("SAST", "SCA", "SECRET", "DAST", "API", "CONTAINER", "IAC", "MOBILE");
    // ^^^ SELALU 8 SCANNER — meski target URL
}
```

**Orchestration (REAL):**
- Creates 8 Scan objects per type
- Async execution via ScanService
- Progress monitoring dengan polling
- Auto-generate report saat selesai

### Kesimpulan:
- Target detection: **Real**
- Scanner selection: **Tidak inteligent** — selalu jalankan semua 8 scanner
- Orchestration: **Real dan functional**
- Progress tracking: **Bagus dan informatif**

### Yang perlu diperbaiki:
- Filter scanner berdasarkan target type
- Coverage planning sebelum scan
- Scope/ROE checking
- Mode selection (PASSIVE/SAFE/DEEP/LAB)

---

## 4. Scanner Plugin System — 2/10

### Apa yang ada di kode:

**TIDAK ADA plugin interface.** Semua analyzer adalah static utility classes:

```java
// SastAnalyzer.java
public class SastAnalyzer {
    public static List<Map<String, Object>> analyze(String content, String fileName) {
        // hardcoded regex rules
    }
}

// ScanService.java — hardcoded switch
private List<String> pluginsFor(String type) {
    return switch (type.toUpperCase()) {
        case "SAST" -> List.of("semgrep", "codeql");  // label saja
        case "SCA" -> List.of("trivy", "grype");       // label saja
        // ...
    };
}

// runRealAnalyzers — hardcoded calls
if ("SAST".equals(type)) {
    sasts = SastAnalyzer.analyze(toAnalyze, fileName);  // direct call
}
if ("SECRET".equals(type)) {
    secrets = SecretAnalyzer.analyze(toAnalyze, fileName);  // direct call
}
```

### Kesimpulan:
- "Plugins" di ScanJob hanyalah **string label** — tidak memuat kode apapun
- Analyzer adalah **hardcoded Java classes** dengan static methods
- Menambah analyzer baru = **modifikasi ScanService.java** langsung
- Tidak ada isolasi/ sandbox antar analyzer

### Yang perlu diperbaiki:
- Buat interface `SecurityScannerPlugin`
- Implementasi `supports()`, `plan()`, `execute()`, `parse()`, `normalize()`, `validate()`
- Isolated execution (thread pool / process / container)
- Plugin discovery via Spring ApplicationContext

---

## 5. Coverage Registry — 0/10

### Apa yang ada di kode:

**TIDAK ADA file coverage module.**

Dashboard coverage:
```java
posture.put("coverage", Map.of(
    "SAST", sastCount > 0 ? "✓" : "○",
    "SCA", scaCount > 0 ? "✓" : "○",
    "SECRET", secretCount > 0 ? "✓" : "○",
    "DAST", "○",      // selalu "○" — HARDCODED
    "API", "○",        // selalu "○"
    "MOBILE", "○",     // selalu "○"
    "CONTAINER", "○",  // selalu "○"
    "CLOUD", "○"       // selalu "○"
));
```

### Kesimpulan:
- Coverage module **tidak ada** di kode
- Dashboard coverage **partially real** (SAST/SCA/SECRET check data) tapi **hardcoded** untuk sisanya
- Tidak ada test registry, tidak ada mapping ke standar (OWASP WSTG, ASVS)

### Yang perlu diperbaiki:
- Buat SecurityCoverageRegistry dengan test definitions
- Map ke OWASP WSTG test IDs, ASVS requirements
- Hitung applicable vs executed vs passed
- Dashboard menampilkan coverage real

---

## 6. Finding Correlation — 1/10

### Apa yang ada di kode:

```java
public Map<String, Object> correlation(UUID findingId) {
    Finding f = get(findingId);
    // Cari finding lain di ASSET YANG SAMA
    List<Finding> sameAsset = findingRepo.findByAssetId(f.getAssetId(), ...);
    // Filter: same CWE ATAU same type
    List<Finding> correlated = sameAsset.stream()
        .filter(x -> !x.getId().equals(f.getId())
            && (Objects.equals(x.getCwe(), f.getCwe())
                || Objects.equals(x.getType(), f.getType())))
        .limit(5).toList();
    // Attack path = string concatenation
    res.put("attackPathCandidate",
        correlated.size() >= 2
            ? "Potential chain: " + f.getType() + " -> " + correlated.get(0).getType()
            : "No strong chain");
}
```

### Kesimpulan:
- Hanya mencari di **asset yang sama** — tidak cross-asset
- Filter: same CWE **ATAU** same type — **sangat longgar**
- Attack path = **string concatenation** — bukan graph traversal
- Limit 5 — arbitrary cap
- Kode sendiri menulis `// naive correlation`

### Yang perlu diperbaiki:
- Cross-asset correlation (findings sharing exploit prerequisites)
- Root-cause deduplication (1 root cause → multiple evidence)
- Temporal correlation (findings yang muncul bersamaan)
- Graph-based attack path reasoning
- Evidence strength scoring

---

## 7. Risk Engine — 7/10

### Apa yang ada di kode:

```java
public double calculate(Finding f) {
    double cvssScore = f.getCvss() != null ? (f.getCvss() / 10.0) * 30 : 15;
    double epssScore = f.getEpss() != null ? f.getEpss() * 15 : 0;
    if (Boolean.TRUE.equals(f.getKev())) epssScore += 12;
    double criticalityScore = switch (...) { "CRITICAL" -> 15; "HIGH" -> 10; ... };
    double exposureScore = 0;
    if (internetExposed) exposureScore += 12;
    if (reachable) exposureScore += 8;
    if ("PRODUCTION".equals(env)) exposureScore += 5;
    double confidenceScore = switch (...) { "CONFIRMED" -> 5; ... };
    double severityScore = switch (...) { "CRITICAL" -> 10; ... };
    double ageScore = ...;
    return Math.max(0, Math.min(100, total));
}
```

### Kesimpulan:
- Multi-factor scoring: **Real dan reasonable**
- Factors: CVSS, EPSS, KEV, criticality, exposure, confidence, severity, age
- Cap 0-100: **Benar**
- SLA calculation: **Real**
- Fingerprint generation: **Real**

**Weaknesses:**
- Additive only — tidak ada multiplicative interaction
- Tidak ada normalization terhadap data real
- Age factor terlalu linear

### Yang perlu diperbaiki:
- Multiplicative interaction (internet-exposed + critical = compound risk)
- Calibration terhadap CVSS/EPSS actual data
- ML-based scoring (optional)
- Finding validation sebelum final scoring

---

## 8. Evidence Collection — 1/10

### Apa yang ada di kode:

```java
Evidence ev = Evidence.builder()
    .findingId(saved.getId())
    .type("SCANNER_RESULT")
    .content("Evidence for " + saved.getTitle())  // <-- PLACEHOLDER
    .author("scanner")
    .sha256(UUID.randomUUID().toString().replace("-",""))  // <-- RANDOM, bukan hash
    .build();
```

### Kesimpulan:
- **Setiap finding** dapat 1 Evidence dengan type `SCANNER_RESULT`
- Content = **string placeholder** — bukan real evidence
- SHA256 = **random UUID** — bukan hash konten sebenarnya
- Entity Evidence punya field `SCREENSHOT`, `HTTP_REQUEST`, `HTTP_RESPONSE` dll — tapi **tidak pernah diisi**

### Yang perlu diperbaiki:
- Real HTTP request/response capture untuk DAST
- Code snippet dengan file path + line number untuk SAST
- Dependency tree untuk SCA
- Screenshot untuk visual verification
- Content hash yang real

---

## 9. Graph / Attack Path — 3/10

### Apa yang ada di kode:

**Graph nodes (REAL):**
```java
for (Asset a : assets) {
    nodes.add(Map.of("id", a.getId(), "label", a.getName(), "type", "asset"));
}
for (Finding f : findings) {
    nodes.add(Map.of("id", f.getId(), "label", f.getTitle(), "type", "vulnerability"));
    edges.add(Map.of("from", f.getAssetId(), "to", f.getId(), "label", "HAS_VULN"));
}
```

**Graph connections (FAKE):**
```java
if (assets.size() >= 3) {
    for (int i = 0; i < Math.min(assets.size()-1, 4); i++) {
        edges.add(Map.of("from", assets.get(i).getId(), "to", assets.get(i+1).getId(), "label", "CONNECTS"));
    }
}
// ^^^ Synthetic — asset A→B→C berdasarkan urutan database
```

**Attack paths (HARDCODED):**
```java
for (Finding f : criticalFindings) {
    attackPaths.add(Map.of(
        "id", "AP-" + counter++,
        "chain", List.of("Internet", f.getAssetName(), "Service", "Database"),
        // ^^^ SELALU template yang sama
        "impact", risk > 80 ? "Confidential Data Exposure" : "Service Disruption"
    ));
}
```

### Kesimpulan:
- Nodes & edges dari **data real** (assets + findings)
- Connections antar asset: **synthetic/fake**
- Attack paths: **hardcoded template** — bukan graph traversal
- Tidak ada shortest-path algorithm
- Tidak ada reachability analysis

### Yang perlu diperbaiki:
- Real network topology mapping
- Graph traversal (Dijkstra/PageRank)
- Data flow analysis
- Exploit chain reasoning
- Cross-asset attack paths

---

## 10. Dashboard — 5/10

### Apa yang ada di kode:

**Real metrics:**
- `critical`, `high`, `totalFindings`, `totalAssets` — dari DB
- `bySeverity` — real aggregation query
- Trend data — real (7 hari terakhir)
- `topRiskAssets` — real

**Problem:**
```java
// Performance: load SELURUH findings ke memory
List<Finding> all = findingRepo.findAll();
long critical = all.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count();
long high = all.stream().filter(f -> "HIGH".equals(f.getSeverity())).count();
long kev = all.stream().filter(f -> Boolean.TRUE.equals(f.getKev())).count();
// ^^^ Diulang 6x — setiap metrik load ulang semua data
```

**Hardcoded:**
```java
m.put("repositories", 8);     // FAKE
m.put("apis", 74);            // FAKE
m.put("mobileApps", 2);       // FAKE
m.put("cloudResources", 137); // FAKE
m.put("containers", 28);      // FAKE
```

### Kesimpulan:
- Core metrics: **Real** tapi **sangat tidak efisien**
- Application dashboard: **hardcoded fake numbers**
- Performance: **catastrophic** untuk dataset besar

### Yang perlu diperbaiki:
- Pakai COUNT queries alih-alih findAll()
- Async dashboard computation
- Cache results
- Hapus hardcoded values

---

## 11. Reporting — 2/10

### Apa yang ada di kode:

```java
public Report generate(UUID projectId, String type, String format, Map<String, Object> params) {
    String draft = aiService.reportDraft(projectId);  // rule-based summary
    Map<String, Object> reportData = Map.of(
        "draft", draft, "stats", stats, "type", type, "generatedAt", Instant.now()
    );
    String content = objectMapper.writeValueAsString(reportData);  // JSON blob
    Report r = Report.builder()
        .filePath("s3://vulnerax-reports/" + projectId + "/" + UUID + ".pdf")  // FAKE PATH
        .status("READY")
        .build();
    reportRepo.save(r);
    return r;
}
```

### Kesimpulan:
- Report = **JSON blob** di database
- filePath = **fake S3 path** — tidak ada upload
- Tidak ada PDF/HTML generation
- Format parameter diabaikan
- export() hanya return stored JSON

### Yang perlu diperbaiki:
- PDF generation (iText, JasperReports, atau wkhtmltopdf)
- HTML report template
- Executive summary vs technical detail
- Compliance report mapping
- Real S3 upload

---

## 12. Testing — 2/10

### Breakdown 44 test files:

**Real logic tests (6-7 files):**
| File | Tests | What it tests |
|------|-------|---------------|
| FindingServiceTest | 8 | CRUD, dedup, status transitions, stats |
| ScanServiceTest | 7 | Create, jobs, cancel |
| AuthServiceTest | 7 | Register, login, password validation |
| JwtTokenProviderTest | 6 | Token generation, validation, tamper |
| FindingControllerTest | 7 | API endpoints dengan mock |
| DashboardControllerTest | 2 | Dashboard endpoints |
| DashboardIntegrationTest | 3 | Integration test |

**Smoke tests (35+ files):**
```java
// Pola yang sama untuk ~35 files:
void list_or_get_returns_ok_or_not_found_but_controller_loads() {
    try {
        mvc.perform(get("/api/v1/xxx")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            assert s != 500;  // <-- hanya cek tidak 500
        });
    } catch (Exception e) { ... }
}
```

### Kesimpulan:
- 6-7 file test **logic real** dengan Mockito
- 35+ file **boilerplate** yang hanya cek "tidak 500"
- Tidak ada test untuk analyzer correctness
- Tidak ada integration test untuk scan execution flow
- Tidak ada E2E test

---

## Overall Assessment

### Strengths (Real)
1. **8 Analyzer implementations** — SAST/SCA/Secret/DAST/API/Mobile/Container/IaC semuanya melakukan analisis real
2. **Risk Engine** — Multi-factor scoring yang legitimate
3. **Finding entity model** — Sangat comprehensive (50+ fields)
4. **Spring conventions** — Proper layered architecture
5. **JWT auth** — Real implementation dengan proper security

### Weaknesses (Hype vs Reality)
1. **Tenant isolation** — Tidak ada di query layer
2. **MFA** — Verification dummy
3. **Coverage registry** — Tidak ada
4. **Plugin system** — Tidak ada
5. **Attack path** — Hardcoded template
6. **Evidence** — Placeholder
7. **Reporting** — JSON blob
8. **Dashboard** — Performance buruk + hardcoded data
9. **Correlation** — Sangat naive

### Gap Terbesar
Dokumentasi dan kode **sangat berjauhan**. PROJECT_SUMMARY.md menyebutkan "Coverage tracking" dan "32 pages" seolah sudah lengkap, tapi module coverage tidak ada, dan banyak hal yang didokumentasikan tidak ada implementasinya.

---

## Rekomendasi Prioritas P0

1. **Tenant Isolation** — Tambah `organizationId` ke semua entity + enforce di query
2. **MFA Real** — Implement TOTP RFC 6238 + recovery codes
3. **Coverage Registry** — Buat test definition registry + map ke OWASP WSTG
4. **Plugin Interface** — Buat `SecurityScannerPlugin` interface
5. **OneClick Intelligence** — Filter scanner berdasarkan target type
6. **Evidence Real** — Replace placeholder dengan real evidence capture
7. **Dashboard Fix** — COUNT queries + hapus hardcoded
8. **Test Quality** — Replace smoke tests dengan real logic tests
