package com.vulnerax;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.container.ContainerImage;
import com.vulnerax.modules.database.DatabaseAsset;
import com.vulnerax.modules.finding.Evidence;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingInstance;
import com.vulnerax.modules.firmware.FirmwareAsset;
import com.vulnerax.modules.mobile.MobileAnalysis;
import com.vulnerax.modules.organization.Organization;
import com.vulnerax.modules.organization.Project;
import com.vulnerax.modules.organization.Workspace;
import com.vulnerax.modules.pentest.PentestEngagement;
import com.vulnerax.modules.reporting.Report;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanJob;
import com.vulnerax.modules.supplychain.ArtifactProvenance;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EntityBuilderCoverageTest {

    @Test
    void findingBuilder_setsAllFields() {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();
        Finding f = Finding.builder()
                .findingId("FND-1001")
                .title("SQL Injection in login")
                .description("Unparameterized query")
                .type("INJECTION")
                .severity("CRITICAL")
                .confidence("HIGH")
                .status("OPEN")
                .projectId(UUID.randomUUID())
                .organizationId(UUID.randomUUID())
                .assetId(UUID.randomUUID())
                .assetName("Web App")
                .environment("PRODUCTION")
                .source("sast-scanner")
                .scanId(UUID.randomUUID())
                .cwe("CWE-89")
                .cweId("CWE-89")
                .cveId("CVE-2024-1234")
                .owasp("A03:2021")
                .masvs("MSTG-NETWORK-01")
                .asvs("V1.2.3")
                .cvss(9.8)
                .epss(0.95)
                .kev(true)
                .internetExposed(true)
                .reachable(true)
                .businessCriticality("CRITICAL")
                .owner("Security Team")
                .filePath("/src/main/java/Auth.java")
                .lineNumber(42)
                .functionName("authenticate")
                .codeSnippet("SELECT * FROM users WHERE id=")
                .dataFlow("input -> query")
                .recommendation("Use parameterized query")
                .evidenceJson("{\"type\":\"SCANNER_RESULT\"}")
                .riskScore(95.0)
                .riskLevel("CRITICAL")
                .compensatingControl("WAF rule")
                .fingerprint("abc123")
                .falsePositive(false)
                .duplicate(false)
                .parentFindingId(UUID.randomUUID())
                .correlationId(UUID.randomUUID())
                .firstSeenAt(now)
                .lastSeenAt(now)
                .slaDueAt(now.plusSeconds(86400))
                .slaStatus("ACTIVE")
                .build();
        f.setId(id);

        assertNotNull(f);
        assertEquals("FND-1001", f.getFindingId());
        assertEquals("SQL Injection in login", f.getTitle());
        assertEquals("INJECTION", f.getType());
        assertEquals("CRITICAL", f.getSeverity());
        assertEquals("HIGH", f.getConfidence());
        assertEquals("OPEN", f.getStatus());
        assertEquals(9.8, f.getCvss());
        assertEquals(0.95, f.getEpss());
        assertTrue(f.getKev());
        assertTrue(f.getInternetExposed());
        assertTrue(f.getReachable());
        assertEquals("CRITICAL", f.getBusinessCriticality());
        assertEquals(42, f.getLineNumber());
        assertEquals("authenticate", f.getFunctionName());
        assertEquals(95.0, f.getRiskScore());
        assertEquals("CRITICAL", f.getRiskLevel());
        assertFalse(f.getFalsePositive());
        assertFalse(f.getDuplicate());
        assertEquals(id, f.getId());
    }

    @Test
    void findingBuilder_defaults() {
        Finding f = Finding.builder()
                .title("Test").type("XSS").severity("MEDIUM").confidence("HIGH").build();

        assertEquals("OPEN", f.getStatus());
        assertFalse(f.getKev());
        assertFalse(f.getInternetExposed());
        assertFalse(f.getReachable());
        assertFalse(f.getFalsePositive());
        assertFalse(f.getDuplicate());
    }

    @Test
    void evidenceBuilder_setsAllFields() {
        UUID findingId = UUID.randomUUID();
        Evidence e = Evidence.builder()
                .findingId(findingId)
                .type("HTTP_REQUEST")
                .content("Response body content")
                .author("dast-analyzer")
                .sha256("abc123hash")
                .requestMethod("POST")
                .requestUrl("https://api.example.com/login")
                .requestBody("{\"user\":\"admin\"}")
                .responseHeaders("Content-Type: application/json")
                .responseStatusCode(200)
                .responseBody("{\"token\":\"xxx\"}")
                .payload("' OR 1=1 --")
                .command("nmap -sV target")
                .commandOutput("PORT 80 OPEN")
                .screenshot("/tmp/screenshot.png")
                .validationHash("valid123")
                .validated(true)
                .responseTimeMs(150L)
                .build();

        assertNotNull(e);
        assertEquals(findingId, e.getFindingId());
        assertEquals("HTTP_REQUEST", e.getType());
        assertEquals("POST", e.getRequestMethod());
        assertEquals("https://api.example.com/login", e.getRequestUrl());
        assertEquals(200, e.getResponseStatusCode());
        assertEquals("' OR 1=1 --", e.getPayload());
        assertTrue(e.isValidated());
        assertEquals(150L, e.getResponseTimeMs());
    }

    @Test
    void artifactProvenanceBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        ArtifactProvenance ap = ArtifactProvenance.builder()
                .projectId(projectId)
                .artifactName("spring-core")
                .version("6.1.0")
                .sbomId(UUID.randomUUID())
                .signatureJson("{\"sig\":\"abc\"}")
                .buildJson("{\"builder\":\"maven\"}")
                .provenanceJson("{\"source\":\"maven-central\"}")
                .verified(true)
                .status("VERIFIED")
                .build();

        assertNotNull(ap);
        assertEquals(projectId, ap.getProjectId());
        assertEquals("spring-core", ap.getArtifactName());
        assertEquals("6.1.0", ap.getVersion());
        assertTrue(ap.getVerified());
        assertEquals("VERIFIED", ap.getStatus());
    }

    @Test
    void artifactProvenanceBuilder_defaults() {
        ArtifactProvenance ap = ArtifactProvenance.builder()
                .projectId(UUID.randomUUID()).artifactName("test").version("1.0").build();

        assertFalse(ap.getVerified());
        assertEquals("ACTIVE", ap.getStatus());
    }

    @Test
    void mobileAnalysisBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(projectId)
                .assetId(UUID.randomUUID())
                .platform("ANDROID")
                .fileName("app.apk")
                .fileSha256("sha256hash")
                .fileSize(1024000L)
                .manifestJson("{\"package\":\"com.test\"}")
                .stringsJson("[\"string1\"]")
                .findingsJson("[\"finding1\"]")
                .certInfo("{\"issuer\":\"CN=Test\"}")
                .masvsScore(75)
                .status("DONE")
                .build();

        assertNotNull(ma);
        assertEquals(projectId, ma.getProjectId());
        assertEquals("ANDROID", ma.getPlatform());
        assertEquals("app.apk", ma.getFileName());
        assertEquals(1024000L, ma.getFileSize());
        assertEquals(75, ma.getMasvsScore());
        assertEquals("DONE", ma.getStatus());
    }

    @Test
    void mobileAnalysisBuilder_defaultMasvsScore() {
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(UUID.randomUUID()).platform("IOS").fileName("app.ipa").build();

        assertEquals(0, ma.getMasvsScore());
    }

    @Test
    void databaseAssetBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        DatabaseAsset da = DatabaseAsset.builder()
                .projectId(projectId)
                .name("Production DB")
                .engine("POSTGRESQL")
                .version("15.4")
                .host("db.example.com")
                .port(5432)
                .exposureJson("{\"exposed\":false}")
                .encryptionJson("{\"atRest\":true}")
                .authJson("{\"mfa\":true}")
                .auditJson("{\"enabled\":true}")
                .riskLevel("LOW")
                .status("ACTIVE")
                .build();

        assertNotNull(da);
        assertEquals(projectId, da.getProjectId());
        assertEquals("Production DB", da.getName());
        assertEquals("POSTGRESQL", da.getEngine());
        assertEquals("15.4", da.getVersion());
        assertEquals("db.example.com", da.getHost());
        assertEquals(5432, da.getPort());
        assertEquals("LOW", da.getRiskLevel());
        assertEquals("ACTIVE", da.getStatus());
    }

    @Test
    void databaseAssetBuilder_defaults() {
        DatabaseAsset da = DatabaseAsset.builder()
                .projectId(UUID.randomUUID()).name("DB").engine("MYSQL").host("localhost").port(3306).build();

        assertEquals("MEDIUM", da.getRiskLevel());
        assertEquals("ACTIVE", da.getStatus());
    }

    @Test
    void scanBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        Instant now = Instant.now();
        Scan s = Scan.builder()
                .projectId(projectId)
                .assetId(UUID.randomUUID())
                .organizationId(UUID.randomUUID())
                .profile("DEEP")
                .scannerType("SAST")
                .scanType("url")
                .status("COMPLETED")
                .target("https://example.com")
                .targetUrl("https://example.com")
                .startedAt(now)
                .finishedAt(now.plusSeconds(300))
                .initiatedBy("admin@test.com")
                .configJson("{\"timeout\":300}")
                .scopeJson("{\"urls\":[\"*\"]}")
                .findingsCount(15)
                .durationMs(300000L)
                .build();

        assertNotNull(s);
        assertEquals(projectId, s.getProjectId());
        assertEquals("DEEP", s.getProfile());
        assertEquals("SAST", s.getScannerType());
        assertEquals("COMPLETED", s.getStatus());
        assertEquals("https://example.com", s.getTarget());
        assertEquals(15, s.getFindingsCount());
        assertEquals(300000L, s.getDurationMs());
    }

    @Test
    void scanBuilder_defaultStatus() {
        Scan s = Scan.builder()
                .projectId(UUID.randomUUID()).profile("STANDARD").scannerType("DAST").build();

        assertEquals("QUEUED", s.getStatus());
    }

    @Test
    void containerImageBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        ContainerImage ci = ContainerImage.builder()
                .projectId(projectId)
                .imageName("nginx")
                .tag("1.25")
                .digest("sha256:abc123")
                .baseImage("ubuntu:22.04")
                .dockerfile("FROM ubuntu:22.04")
                .packagesJson("[\"openssl\"]")
                .cveJson("[\"CVE-2024-1234\"]")
                .misconfigJson("[\"privilege escalation\"]")
                .secretJson("[\"hardcoded key\"]")
                .riskLevel("HIGH")
                .status("ACTIVE")
                .build();

        assertNotNull(ci);
        assertEquals(projectId, ci.getProjectId());
        assertEquals("nginx", ci.getImageName());
        assertEquals("1.25", ci.getTag());
        assertEquals("sha256:abc123", ci.getDigest());
        assertEquals("ubuntu:22.04", ci.getBaseImage());
        assertEquals("HIGH", ci.getRiskLevel());
    }

    @Test
    void containerImageBuilder_defaults() {
        ContainerImage ci = ContainerImage.builder()
                .projectId(UUID.randomUUID()).imageName("app").build();

        assertEquals("latest", ci.getTag());
        assertEquals("[]", ci.getPackagesJson());
        assertEquals("[]", ci.getCveJson());
        assertEquals("[]", ci.getMisconfigJson());
        assertEquals("[]", ci.getSecretJson());
        assertEquals("MEDIUM", ci.getRiskLevel());
        assertEquals("ACTIVE", ci.getStatus());
    }

    @Test
    void pentestEngagementBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        Instant now = Instant.now();
        PentestEngagement pe = PentestEngagement.builder()
                .projectId(projectId)
                .clientName("Acme Corp")
                .scope("Full web application + API")
                .rulesOfEngagement("No DoS attacks")
                .testWindowStart(now)
                .testWindowEnd(now.plusSeconds(604800))
                .status("IN_PROGRESS")
                .testersJson("[\"tester1@test.com\"]")
                .assetsJson("[\"api.example.com\"]")
                .methodology("OWASP WSTG")
                .environment("STAGING")
                .build();

        assertNotNull(pe);
        assertEquals(projectId, pe.getProjectId());
        assertEquals("Acme Corp", pe.getClientName());
        assertEquals("Full web application + API", pe.getScope());
        assertEquals("IN_PROGRESS", pe.getStatus());
        assertEquals("OWASP WSTG", pe.getMethodology());
        assertEquals("STAGING", pe.getEnvironment());
    }

    @Test
    void pentestEngagementBuilder_defaults() {
        PentestEngagement pe = PentestEngagement.builder()
                .projectId(UUID.randomUUID()).clientName("Test").scope("scope").build();

        assertEquals("PLANNING", pe.getStatus());
        assertEquals("[]", pe.getTestersJson());
        assertEquals("[]", pe.getAssetsJson());
        assertEquals("OWASP WSTG", pe.getMethodology());
        assertEquals("STAGING", pe.getEnvironment());
    }

    @Test
    void firmwareAssetBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        FirmwareAsset fa = FirmwareAsset.builder()
                .projectId(projectId)
                .name("Router FW")
                .version("3.2.1")
                .fileName("firmware.bin")
                .fileSize(52428800L)
                .sha256("sha256hash")
                .filesystemJson("{\"paths\":[\"/etc\"]}")
                .binariesJson("[\"busybox\"]")
                .cveJson("[\"CVE-2024-5678\"]")
                .riskLevel("CRITICAL")
                .status("ACTIVE")
                .build();

        assertNotNull(fa);
        assertEquals(projectId, fa.getProjectId());
        assertEquals("Router FW", fa.getName());
        assertEquals("3.2.1", fa.getVersion());
        assertEquals("firmware.bin", fa.getFileName());
        assertEquals(52428800L, fa.getFileSize());
        assertEquals("CRITICAL", fa.getRiskLevel());
    }

    @Test
    void firmwareAssetBuilder_defaults() {
        FirmwareAsset fa = FirmwareAsset.builder()
                .projectId(UUID.randomUUID()).name("FW").fileName("fw.bin").build();

        assertEquals("[]", fa.getBinariesJson());
        assertEquals("[]", fa.getCveJson());
        assertEquals("MEDIUM", fa.getRiskLevel());
        assertEquals("ACTIVE", fa.getStatus());
    }

    @Test
    void scanJobBuilder_setsAllFields() {
        UUID scanId = UUID.randomUUID();
        ScanJob sj = ScanJob.builder()
                .scanId(scanId)
                .scannerPlugin("sast-plugin")
                .status("COMPLETED")
                .workerId("worker-1")
                .logs("Analysis complete")
                .progress(100)
                .resultJson("{\"findings\":5}")
                .error(null)
                .build();

        assertNotNull(sj);
        assertEquals(scanId, sj.getScanId());
        assertEquals("sast-plugin", sj.getScannerPlugin());
        assertEquals("COMPLETED", sj.getStatus());
        assertEquals("worker-1", sj.getWorkerId());
        assertEquals(100, sj.getProgress());
    }

    @Test
    void scanJobBuilder_defaultStatus() {
        ScanJob sj = ScanJob.builder()
                .scanId(UUID.randomUUID()).scannerPlugin("dast-plugin").build();

        assertEquals("QUEUED", sj.getStatus());
    }

    @Test
    void reportBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        Report r = Report.builder()
                .projectId(projectId)
                .type("EXECUTIVE")
                .title("Security Report Q4")
                .format("PDF")
                .status("READY")
                .contentJson("{\"sections\":[\"executive\"]}")
                .generatedBy("system")
                .filePath("s3://reports/report.pdf")
                .classification("CONFIDENTIAL")
                .build();

        assertNotNull(r);
        assertEquals(projectId, r.getProjectId());
        assertEquals("EXECUTIVE", r.getType());
        assertEquals("READY", r.getStatus());
        assertEquals("CONFIDENTIAL", r.getClassification());
    }

    @Test
    void reportBuilder_defaultStatus() {
        Report r = Report.builder()
                .projectId(UUID.randomUUID()).type("TECHNICAL").title("Test").build();

        assertEquals("DRAFT", r.getStatus());
    }

    @Test
    void organizationBuilder_setsAllFields() {
        Organization o = Organization.builder()
                .name("Acme Corp")
                .slug("acme-corp")
                .description("Test org")
                .tier("ENTERPRISE")
                .active(true)
                .build();

        assertNotNull(o);
        assertEquals("Acme Corp", o.getName());
        assertEquals("acme-corp", o.getSlug());
        assertTrue(o.getActive());
    }

    @Test
    void organizationBuilder_defaults() {
        Organization o = Organization.builder().name("Test").slug("test").build();

        assertEquals("ENTERPRISE", o.getTier());
        assertTrue(o.getActive());
    }

    @Test
    void workspaceBuilder_setsAllFields() {
        UUID orgId = UUID.randomUUID();
        Workspace w = Workspace.builder()
                .name("Production")
                .organizationId(orgId)
                .description("Prod workspace")
                .environment("PRODUCTION")
                .build();

        assertNotNull(w);
        assertEquals("Production", w.getName());
        assertEquals(orgId, w.getOrganizationId());
        assertEquals("PRODUCTION", w.getEnvironment());
    }

    @Test
    void workspaceBuilder_defaultEnvironment() {
        Workspace w = Workspace.builder().name("Test").organizationId(UUID.randomUUID()).build();

        assertEquals("PRODUCTION", w.getEnvironment());
    }

    @Test
    void projectBuilder_setsAllFields() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        Project p = Project.builder()
                .name("Web App")
                .workspaceId(wsId)
                .organizationId(orgId)
                .description("Main project")
                .criticality("CRITICAL")
                .status("ACTIVE")
                .businessUnit("Engineering")
                .techLead("lead@test.com")
                .securityChampion("sec@test.com")
                .build();

        assertNotNull(p);
        assertEquals("Web App", p.getName());
        assertEquals(wsId, p.getWorkspaceId());
        assertEquals(orgId, p.getOrganizationId());
        assertEquals("CRITICAL", p.getCriticality());
        assertEquals("Engineering", p.getBusinessUnit());
    }

    @Test
    void projectBuilder_defaults() {
        Project p = Project.builder().name("Test").workspaceId(UUID.randomUUID()).organizationId(UUID.randomUUID()).build();

        assertEquals("HIGH", p.getCriticality());
        assertEquals("ACTIVE", p.getStatus());
    }

    @Test
    void assetBuilder_setsAllFields() {
        UUID projectId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        Asset a = Asset.builder()
                .projectId(projectId)
                .organizationId(orgId)
                .workspaceId(UUID.randomUUID())
                .name("Payment API")
                .type("API")
                .identifier("https://api.pay.com")
                .version("2.1.0")
                .environment("PRODUCTION")
                .criticality("CRITICAL")
                .dataClassification("RESTRICTED")
                .internetExposed(true)
                .managed(true)
                .status("ACTIVE")
                .technology("JAVA")
                .owner("Payments Team")
                .team("Backend")
                .location("us-east-1")
                .tags("payment,critical")
                .metadataJson("{\"framework\":\"spring\"}")
                .discoverySource("MANUAL")
                .build();

        assertNotNull(a);
        assertEquals(projectId, a.getProjectId());
        assertEquals(orgId, a.getOrganizationId());
        assertEquals("Payment API", a.getName());
        assertEquals("API", a.getType());
        assertEquals("CRITICAL", a.getCriticality());
        assertTrue(a.getInternetExposed());
        assertEquals("JAVA", a.getTechnology());
    }

    @Test
    void assetBuilder_defaults() {
        Asset a = Asset.builder().projectId(UUID.randomUUID()).organizationId(UUID.randomUUID())
                .name("Test").type("DOMAIN").build();

        assertEquals("MEDIUM", a.getCriticality());
        assertEquals("INTERNAL", a.getDataClassification());
        assertFalse(a.getInternetExposed());
        assertTrue(a.getManaged());
        assertEquals("ACTIVE", a.getStatus());
        assertEquals("UNKNOWN", a.getTechnology());
    }

    @Test
    void findingInstanceBuilder_setsAllFields() {
        UUID findingId = UUID.randomUUID();
        FindingInstance fi = FindingInstance.builder()
                .findingId(findingId)
                .assetName("Web App")
                .location("/src/main.java:42")
                .scanner("sast-scanner")
                .evidence("Code snippet evidence")
                .fingerprint("abc123")
                .build();

        assertNotNull(fi);
        assertEquals(findingId, fi.getFindingId());
        assertEquals("Web App", fi.getAssetName());
        assertEquals("/src/main.java:42", fi.getLocation());
        assertEquals("sast-scanner", fi.getScanner());
    }
}
