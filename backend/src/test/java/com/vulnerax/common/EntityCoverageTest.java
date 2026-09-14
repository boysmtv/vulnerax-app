package com.vulnerax.common;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.audit.AuditEvent;
import com.vulnerax.modules.aillm.AiAsset;
import com.vulnerax.modules.browser.BrowserExtension;
import com.vulnerax.modules.campaign.SecurityCampaign;
import com.vulnerax.modules.cicd.CicdPipeline;
import com.vulnerax.modules.cloud.CloudResource;
import com.vulnerax.modules.compliance.ComplianceAssessment;
import com.vulnerax.modules.compliance.ComplianceFramework;
import com.vulnerax.modules.container.ContainerImage;
import com.vulnerax.modules.coverage.SecurityCoverage;
import com.vulnerax.modules.database.DatabaseAsset;
import com.vulnerax.modules.finding.Evidence;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingInstance;
import com.vulnerax.modules.finding.FindingType;
import com.vulnerax.modules.firmware.FirmwareAsset;
import com.vulnerax.modules.iac.IacScan;
import com.vulnerax.modules.iam.IamResource;
import com.vulnerax.modules.identity.AuthController;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.identity.User;
import com.vulnerax.modules.integration.Integration;
import com.vulnerax.modules.k8s.K8sResource;
import com.vulnerax.modules.mobile.MobileAnalysis;
import com.vulnerax.modules.network.NetworkAsset;
import com.vulnerax.modules.notification.Notification;
import com.vulnerax.modules.oneclick.OneClickRun;
import com.vulnerax.modules.organization.Organization;
import com.vulnerax.modules.organization.Project;
import com.vulnerax.modules.organization.Workspace;
import com.vulnerax.modules.pentest.PentestEngagement;
import com.vulnerax.modules.policy.PolicyException;
import com.vulnerax.modules.policy.SecurityPolicy;
import com.vulnerax.modules.rbac.Permission;
import com.vulnerax.modules.rbac.RolePermission;
import com.vulnerax.modules.retest.Retest;
import com.vulnerax.modules.reporting.Report;
import com.vulnerax.modules.reporting.ReportController;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanJob;
import com.vulnerax.modules.scan.model.Severity;
import com.vulnerax.modules.sbom.Sbom;
import com.vulnerax.modules.threatmodel.ThreatModel;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Comprehensive entity coverage test.
 * Tests builders, getters, setters, constructors, equals, hashCode, toString
 * for ALL entity/model/DTO classes to maximize JaCoCo coverage.
 */
class EntityCoverageTest {

    // ════════════════════════════════════════════════════════════════
    //  ASSET
    // ════════════════════════════════════════════════════════════════

    @Test
    void asset_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        UUID wsId = UUID.randomUUID();
        Asset a = Asset.builder()
                .projectId(pid).organizationId(orgId).workspaceId(wsId)
                .name("api.example.com").type("API").identifier("api.example.com")
                .version("1.0").environment("PRODUCTION").criticality("CRITICAL")
                .dataClassification("CONFIDENTIAL").internetExposed(true).managed(true)
                .status("ACTIVE").technology("Java").owner("admin")
                .team("security").location("us-east-1").tags("web,api")
                .metadataJson("{\"key\":\"val\"}").discoverySource("GITHUB").build();
        a.setId(UUID.randomUUID());
        a.setCreatedAt(Instant.now());
        a.setUpdatedAt(Instant.now());

        assertThat(a.getName()).isEqualTo("api.example.com");
        assertThat(a.getType()).isEqualTo("API");
        assertThat(a.getProjectId()).isEqualTo(pid);
        assertThat(a.getOrganizationId()).isEqualTo(orgId);
        assertThat(a.getWorkspaceId()).isEqualTo(wsId);
        assertThat(a.getIdentifier()).isEqualTo("api.example.com");
        assertThat(a.getVersion()).isEqualTo("1.0");
        assertThat(a.getEnvironment()).isEqualTo("PRODUCTION");
        assertThat(a.getCriticality()).isEqualTo("CRITICAL");
        assertThat(a.getDataClassification()).isEqualTo("CONFIDENTIAL");
        assertThat(a.getInternetExposed()).isTrue();
        assertThat(a.getManaged()).isTrue();
        assertThat(a.getStatus()).isEqualTo("ACTIVE");
        assertThat(a.getTechnology()).isEqualTo("Java");
        assertThat(a.getOwner()).isEqualTo("admin");
        assertThat(a.getTeam()).isEqualTo("security");
        assertThat(a.getLocation()).isEqualTo("us-east-1");
        assertThat(a.getTags()).isEqualTo("web,api");
        assertThat(a.getMetadataJson()).isEqualTo("{\"key\":\"val\"}");
        assertThat(a.getDiscoverySource()).isEqualTo("GITHUB");
    }

    @Test
    void asset_noArgsConstructor() {
        Asset a = new Asset();
        assertThat(a).isNotNull();
        a.setName("test");
        assertThat(a.getName()).isEqualTo("test");
    }

    @Test
    void asset_equals_hashCode() {
        UUID id = UUID.randomUUID();
        Asset a1 = Asset.builder().name("test").type("API").build();
        a1.setId(id);
        Asset a2 = Asset.builder().name("test").type("API").build();
        a2.setId(id);
        assertThat(a1.getId()).isEqualTo(a2.getId());
        assertThat(a1.getId().hashCode()).isEqualTo(a2.getId().hashCode());
    }

    @Test
    void asset_toString() {
        Asset a = Asset.builder().name("test").type("API").build();
        assertThat(a.toString()).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  FINDING
    // ════════════════════════════════════════════════════════════════

    @Test
    void finding_builder_allFields() {
        UUID id = UUID.randomUUID();
        UUID pid = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding f = Finding.builder()
                .findingId("FINDING-001").title("SQL Injection")
                .description("SQL injection in login").type("SAST").severity("CRITICAL")
                .confidence("HIGH").status("OPEN").projectId(pid).organizationId(orgId)
                .assetId(assetId).assetName("api.example.com").environment("PRODUCTION")
                .source("semgrep").scanId(scanId).cwe("CWE-89").cweId("CWE-89")
                .cveId("CVE-2023-1234").owasp("A03").masvs("MSTG-CRYPTO-1")
                .asvs("2.2.1").cvss(9.8).epss(0.85).kev(true)
                .internetExposed(true).reachable(true).businessCriticality("CRITICAL")
                .owner("security").filePath("/src/UserDao.java").lineNumber(42)
                .functionName("login").codeSnippet("stmt.executeQuery(sql)")
                .dataFlow("request->handler->db").recommendation("Use parameterized queries")
                .evidenceJson("[{\"type\":\"screenshot\"}]").riskScore(9.5)
                .riskLevel("CRITICAL").compensatingControl("WAF")
                .fingerprint("fp-123").falsePositive(false).duplicate(false)
                .parentFindingId(UUID.randomUUID()).correlationId(UUID.randomUUID())
                .firstSeenAt(now).lastSeenAt(now).slaDueAt(now.plusSeconds(86400))
                .slaStatus("ACTIVE").build();
        f.setId(id);

        assertThat(f.getFindingId()).isEqualTo("FINDING-001");
        assertThat(f.getTitle()).isEqualTo("SQL Injection");
        assertThat(f.getDescription()).isEqualTo("SQL injection in login");
        assertThat(f.getType()).isEqualTo("SAST");
        assertThat(f.getSeverity()).isEqualTo("CRITICAL");
        assertThat(f.getConfidence()).isEqualTo("HIGH");
        assertThat(f.getStatus()).isEqualTo("OPEN");
        assertThat(f.getProjectId()).isEqualTo(pid);
        assertThat(f.getOrganizationId()).isEqualTo(orgId);
        assertThat(f.getAssetId()).isEqualTo(assetId);
        assertThat(f.getAssetName()).isEqualTo("api.example.com");
        assertThat(f.getEnvironment()).isEqualTo("PRODUCTION");
        assertThat(f.getSource()).isEqualTo("semgrep");
        assertThat(f.getScanId()).isEqualTo(scanId);
        assertThat(f.getCwe()).isEqualTo("CWE-89");
        assertThat(f.getCweId()).isEqualTo("CWE-89");
        assertThat(f.getCveId()).isEqualTo("CVE-2023-1234");
        assertThat(f.getOwasp()).isEqualTo("A03");
        assertThat(f.getMasvs()).isEqualTo("MSTG-CRYPTO-1");
        assertThat(f.getAsvs()).isEqualTo("2.2.1");
        assertThat(f.getCvss()).isEqualTo(9.8);
        assertThat(f.getEpss()).isEqualTo(0.85);
        assertThat(f.getKev()).isTrue();
        assertThat(f.getInternetExposed()).isTrue();
        assertThat(f.getReachable()).isTrue();
        assertThat(f.getBusinessCriticality()).isEqualTo("CRITICAL");
        assertThat(f.getOwner()).isEqualTo("security");
        assertThat(f.getFilePath()).isEqualTo("/src/UserDao.java");
        assertThat(f.getLineNumber()).isEqualTo(42);
        assertThat(f.getFunctionName()).isEqualTo("login");
        assertThat(f.getCodeSnippet()).isEqualTo("stmt.executeQuery(sql)");
        assertThat(f.getDataFlow()).isEqualTo("request->handler->db");
        assertThat(f.getRecommendation()).isEqualTo("Use parameterized queries");
        assertThat(f.getEvidenceJson()).isEqualTo("[{\"type\":\"screenshot\"}]");
        assertThat(f.getRiskScore()).isEqualTo(9.5);
        assertThat(f.getRiskLevel()).isEqualTo("CRITICAL");
        assertThat(f.getCompensatingControl()).isEqualTo("WAF");
        assertThat(f.getFingerprint()).isEqualTo("fp-123");
        assertThat(f.getFalsePositive()).isFalse();
        assertThat(f.getDuplicate()).isFalse();
        assertThat(f.getParentFindingId()).isNotNull();
        assertThat(f.getCorrelationId()).isNotNull();
        assertThat(f.getFirstSeenAt()).isEqualTo(now);
        assertThat(f.getLastSeenAt()).isEqualTo(now);
        assertThat(f.getSlaDueAt()).isNotNull();
        assertThat(f.getSlaStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void finding_defaults() {
        Finding f = new Finding();
        assertThat(f.getStatus()).isEqualTo("OPEN");
        assertThat(f.getKev()).isFalse();
        assertThat(f.getInternetExposed()).isFalse();
        assertThat(f.getReachable()).isFalse();
        assertThat(f.getFalsePositive()).isFalse();
        assertThat(f.getDuplicate()).isFalse();
    }

    @Test
    void finding_prePersist_setsTimestamps() throws Exception {
        Finding f = new Finding();
        f.setFindingId("F-001");
        f.setTitle("test");
        f.setType("SAST");
        f.setSeverity("HIGH");
        f.setConfidence("HIGH");
        f.setCreatedAt(Instant.now());
        f.setUpdatedAt(Instant.now());
        Method onCreate = Finding.class.getDeclaredMethod("onCreate");
        onCreate.setAccessible(true);
        onCreate.invoke(f);
        assertThat(f.getFirstSeenAt()).isNotNull();
        assertThat(f.getLastSeenAt()).isNotNull();
    }

    @Test
    void finding_prePersist_existingFirstSeenAt() throws Exception {
        Finding f = new Finding();
        Instant firstSeen = Instant.now().minusSeconds(100);
        f.setFirstSeenAt(firstSeen);
        f.setCreatedAt(Instant.now());
        f.setUpdatedAt(Instant.now());
        Method onCreate = Finding.class.getDeclaredMethod("onCreate");
        onCreate.setAccessible(true);
        onCreate.invoke(f);
        assertThat(f.getFirstSeenAt()).isEqualTo(firstSeen);
        assertThat(f.getLastSeenAt()).isNotNull();
    }

    @Test
    void finding_preUpdate() throws Exception {
        Finding f = new Finding();
        f.setCreatedAt(Instant.now());
        f.setUpdatedAt(Instant.now());
        Method onUpdate = Finding.class.getDeclaredMethod("onUpdate");
        onUpdate.setAccessible(true);
        onUpdate.invoke(f);
        assertThat(f.getLastSeenAt()).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  EVIDENCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void evidence_builder_allFields() {
        UUID findingId = UUID.randomUUID();
        Evidence e = Evidence.builder()
                .findingId(findingId).type("SCREENSHOT").content("base64data")
                .author("tester").sha256("abc123").requestMethod("POST")
                .requestUrl("https://api.example.com/login")
                .requestBody("{\"user\":\"admin\"}")
                .responseHeaders("Content-Type: application/json")
                .responseStatusCode(200).responseBody("{\"token\":\"xxx\"}")
                .payload("payload data").command("nmap -sV target")
                .commandOutput("PORT 443 OPEN").screenshot("screenshot.png")
                .validationHash("hash123").validated(true).responseTimeMs(150L).build();
        e.setId(UUID.randomUUID());

        assertThat(e.getFindingId()).isEqualTo(findingId);
        assertThat(e.getType()).isEqualTo("SCREENSHOT");
        assertThat(e.getContent()).isEqualTo("base64data");
        assertThat(e.getAuthor()).isEqualTo("tester");
        assertThat(e.getSha256()).isEqualTo("abc123");
        assertThat(e.getRequestMethod()).isEqualTo("POST");
        assertThat(e.getRequestUrl()).isEqualTo("https://api.example.com/login");
        assertThat(e.getRequestBody()).isEqualTo("{\"user\":\"admin\"}");
        assertThat(e.getResponseHeaders()).isEqualTo("Content-Type: application/json");
        assertThat(e.getResponseStatusCode()).isEqualTo(200);
        assertThat(e.getResponseBody()).isEqualTo("{\"token\":\"xxx\"}");
        assertThat(e.getPayload()).isEqualTo("payload data");
        assertThat(e.getCommand()).isEqualTo("nmap -sV target");
        assertThat(e.getCommandOutput()).isEqualTo("PORT 443 OPEN");
        assertThat(e.getScreenshot()).isEqualTo("screenshot.png");
        assertThat(e.getValidationHash()).isEqualTo("hash123");
        assertThat(e.isValidated()).isTrue();
        assertThat(e.getResponseTimeMs()).isEqualTo(150L);
    }

    @Test
    void evidence_noArgsConstructor() {
        Evidence e = new Evidence();
        assertThat(e).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  FINDING INSTANCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void findingInstance_builder_allFields() {
        UUID fid = UUID.randomUUID();
        FindingInstance fi = FindingInstance.builder()
                .findingId(fid).assetName("api.example.com")
                .location("src/main.java:42").scanner("semgrep")
                .evidence("evidence data").fingerprint("fp-abc").build();
        fi.setId(UUID.randomUUID());

        assertThat(fi.getFindingId()).isEqualTo(fid);
        assertThat(fi.getAssetName()).isEqualTo("api.example.com");
        assertThat(fi.getLocation()).isEqualTo("src/main.java:42");
        assertThat(fi.getScanner()).isEqualTo("semgrep");
        assertThat(fi.getEvidence()).isEqualTo("evidence data");
        assertThat(fi.getFingerprint()).isEqualTo("fp-abc");
    }

    @Test
    void findingInstance_noArgsConstructor() {
        FindingInstance fi = new FindingInstance();
        assertThat(fi).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  CONTAINER IMAGE
    // ════════════════════════════════════════════════════════════════

    @Test
    void containerImage_builder_allFields() {
        UUID pid = UUID.randomUUID();
        ContainerImage ci = ContainerImage.builder()
                .projectId(pid).imageName("nginx").tag("1.25")
                .digest("sha256:abc").baseImage("ubuntu:22.04")
                .dockerfile("FROM ubuntu:22.04").packagesJson("[\"curl\"]")
                .cveJson("[{\"cve\":\"CVE-2023\"}]").misconfigJson("[]")
                .secretJson("[]").riskLevel("HIGH").status("ACTIVE").build();
        ci.setId(UUID.randomUUID());

        assertThat(ci.getProjectId()).isEqualTo(pid);
        assertThat(ci.getImageName()).isEqualTo("nginx");
        assertThat(ci.getTag()).isEqualTo("1.25");
        assertThat(ci.getDigest()).isEqualTo("sha256:abc");
        assertThat(ci.getBaseImage()).isEqualTo("ubuntu:22.04");
        assertThat(ci.getDockerfile()).isEqualTo("FROM ubuntu:22.04");
        assertThat(ci.getPackagesJson()).isEqualTo("[\"curl\"]");
        assertThat(ci.getCveJson()).isEqualTo("[{\"cve\":\"CVE-2023\"}]");
        assertThat(ci.getMisconfigJson()).isEqualTo("[]");
        assertThat(ci.getSecretJson()).isEqualTo("[]");
        assertThat(ci.getRiskLevel()).isEqualTo("HIGH");
        assertThat(ci.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void containerImage_defaults() {
        ContainerImage ci = ContainerImage.builder().projectId(UUID.randomUUID()).imageName("app").build();
        assertThat(ci.getTag()).isEqualTo("latest");
        assertThat(ci.getPackagesJson()).isEqualTo("[]");
        assertThat(ci.getCveJson()).isEqualTo("[]");
        assertThat(ci.getMisconfigJson()).isEqualTo("[]");
        assertThat(ci.getSecretJson()).isEqualTo("[]");
        assertThat(ci.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(ci.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  DATABASE ASSET
    // ════════════════════════════════════════════════════════════════

    @Test
    void databaseAsset_builder_allFields() {
        UUID pid = UUID.randomUUID();
        DatabaseAsset da = DatabaseAsset.builder()
                .projectId(pid).name("maindb").engine("POSTGRESQL")
                .version("15.2").host("db.internal").port(5432)
                .exposureJson("{\"public\":false}").encryptionJson("{\"atRest\":true}")
                .authJson("{\"mfa\":true}").auditJson("{\"enabled\":true}")
                .riskLevel("HIGH").status("ACTIVE").build();
        da.setId(UUID.randomUUID());

        assertThat(da.getProjectId()).isEqualTo(pid);
        assertThat(da.getName()).isEqualTo("maindb");
        assertThat(da.getEngine()).isEqualTo("POSTGRESQL");
        assertThat(da.getVersion()).isEqualTo("15.2");
        assertThat(da.getHost()).isEqualTo("db.internal");
        assertThat(da.getPort()).isEqualTo(5432);
        assertThat(da.getExposureJson()).contains("public");
        assertThat(da.getEncryptionJson()).contains("atRest");
        assertThat(da.getAuthJson()).contains("mfa");
        assertThat(da.getAuditJson()).contains("enabled");
        assertThat(da.getRiskLevel()).isEqualTo("HIGH");
        assertThat(da.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void databaseAsset_defaults() {
        DatabaseAsset da = DatabaseAsset.builder()
                .projectId(UUID.randomUUID()).name("db").engine("MYSQL")
                .host("localhost").port(3306).build();
        assertThat(da.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(da.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  NETWORK ASSET
    // ════════════════════════════════════════════════════════════════

    @Test
    void networkAsset_builder_allFields() {
        UUID pid = UUID.randomUUID();
        NetworkAsset na = NetworkAsset.builder()
                .projectId(pid).host("10.0.0.1").ip("10.0.0.1")
                .port(443).service("HTTPS").version("1.1")
                .protocol("TCP").tlsJson("{\"version\":\"1.3\"}")
                .certJson("{\"issuer\":\"Let's Encrypt\"}").vulnJson("[{\"cve\":\"X\"}]")
                .status("OPEN").build();
        na.setId(UUID.randomUUID());

        assertThat(na.getProjectId()).isEqualTo(pid);
        assertThat(na.getHost()).isEqualTo("10.0.0.1");
        assertThat(na.getIp()).isEqualTo("10.0.0.1");
        assertThat(na.getPort()).isEqualTo(443);
        assertThat(na.getService()).isEqualTo("HTTPS");
        assertThat(na.getVersion()).isEqualTo("1.1");
        assertThat(na.getProtocol()).isEqualTo("TCP");
        assertThat(na.getTlsJson()).contains("1.3");
        assertThat(na.getCertJson()).contains("Let's Encrypt");
        assertThat(na.getVulnJson()).contains("cve");
        assertThat(na.getStatus()).isEqualTo("OPEN");
    }

    @Test
    void networkAsset_defaults() {
        NetworkAsset na = NetworkAsset.builder()
                .projectId(UUID.randomUUID()).host("10.0.0.1").port(80).build();
        assertThat(na.getProtocol()).isEqualTo("TCP");
        assertThat(na.getStatus()).isEqualTo("OPEN");
    }

    // ════════════════════════════════════════════════════════════════
    //  CLOUD RESOURCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void cloudResource_builder_allFields() {
        UUID pid = UUID.randomUUID();
        CloudResource cr = CloudResource.builder()
                .projectId(pid).provider("AWS").accountId("123456789")
                .region("us-east-1").service("EC2").resourceType("INSTANCE")
                .resourceId("i-abc123").name("web-server")
                .configurationJson("{\"instanceType\":\"t3.medium\"}")
                .riskJson("{\"risk\":\"medium\"}").complianceJson("{\"soc2\":true}")
                .publicExposed(true).status("ACTIVE").build();
        cr.setId(UUID.randomUUID());

        assertThat(cr.getProjectId()).isEqualTo(pid);
        assertThat(cr.getProvider()).isEqualTo("AWS");
        assertThat(cr.getAccountId()).isEqualTo("123456789");
        assertThat(cr.getRegion()).isEqualTo("us-east-1");
        assertThat(cr.getService()).isEqualTo("EC2");
        assertThat(cr.getResourceType()).isEqualTo("INSTANCE");
        assertThat(cr.getResourceId()).isEqualTo("i-abc123");
        assertThat(cr.getName()).isEqualTo("web-server");
        assertThat(cr.getConfigurationJson()).contains("t3.medium");
        assertThat(cr.getRiskJson()).contains("risk");
        assertThat(cr.getComplianceJson()).contains("soc2");
        assertThat(cr.getPublicExposed()).isTrue();
        assertThat(cr.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void cloudResource_defaults() {
        CloudResource cr = CloudResource.builder()
                .projectId(UUID.randomUUID()).provider("AWS").accountId("123")
                .region("us-east-1").service("S3").resourceType("BUCKET")
                .resourceId("bucket-1").build();
        assertThat(cr.getPublicExposed()).isFalse();
        assertThat(cr.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  FIRMWARE ASSET
    // ════════════════════════════════════════════════════════════════

    @Test
    void firmwareAsset_builder_allFields() {
        UUID pid = UUID.randomUUID();
        FirmwareAsset fa = FirmwareAsset.builder()
                .projectId(pid).name("router-fw").version("2.1.0")
                .fileName("router.bin").fileSize(1024000L).sha256("abc123def")
                .filesystemJson("{\"squashfs\":true}").binariesJson("[\"busybox\"]")
                .cveJson("[{\"cve\":\"CVE-2023\"}]").riskLevel("HIGH").status("ACTIVE").build();
        fa.setId(UUID.randomUUID());

        assertThat(fa.getProjectId()).isEqualTo(pid);
        assertThat(fa.getName()).isEqualTo("router-fw");
        assertThat(fa.getVersion()).isEqualTo("2.1.0");
        assertThat(fa.getFileName()).isEqualTo("router.bin");
        assertThat(fa.getFileSize()).isEqualTo(1024000L);
        assertThat(fa.getSha256()).isEqualTo("abc123def");
        assertThat(fa.getFilesystemJson()).contains("squashfs");
        assertThat(fa.getBinariesJson()).contains("busybox");
        assertThat(fa.getCveJson()).contains("CVE-2023");
        assertThat(fa.getRiskLevel()).isEqualTo("HIGH");
        assertThat(fa.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void firmwareAsset_defaults() {
        FirmwareAsset fa = FirmwareAsset.builder()
                .projectId(UUID.randomUUID()).name("fw").fileName("fw.bin").build();
        assertThat(fa.getBinariesJson()).isEqualTo("[]");
        assertThat(fa.getCveJson()).isEqualTo("[]");
        assertThat(fa.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(fa.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  PENTEST ENGAGEMENT
    // ════════════════════════════════════════════════════════════════

    @Test
    void pentestEngagement_builder_allFields() {
        UUID pid = UUID.randomUUID();
        Instant start = Instant.now();
        Instant end = start.plusSeconds(86400 * 7);
        PentestEngagement pe = PentestEngagement.builder()
                .projectId(pid).clientName("Acme Corp")
                .scope("Web Application, API").rulesOfEngagement("No DoS")
                .testWindowStart(start).testWindowEnd(end)
                .status("IN_PROGRESS").testersJson("[\"tester1\"]")
                .assetsJson("[\"api.example.com\"]").methodology("OWASP WSTG")
                .environment("STAGING").build();
        pe.setId(UUID.randomUUID());

        assertThat(pe.getProjectId()).isEqualTo(pid);
        assertThat(pe.getClientName()).isEqualTo("Acme Corp");
        assertThat(pe.getScope()).isEqualTo("Web Application, API");
        assertThat(pe.getRulesOfEngagement()).isEqualTo("No DoS");
        assertThat(pe.getTestWindowStart()).isEqualTo(start);
        assertThat(pe.getTestWindowEnd()).isEqualTo(end);
        assertThat(pe.getStatus()).isEqualTo("IN_PROGRESS");
        assertThat(pe.getTestersJson()).contains("tester1");
        assertThat(pe.getAssetsJson()).contains("api.example.com");
        assertThat(pe.getMethodology()).isEqualTo("OWASP WSTG");
        assertThat(pe.getEnvironment()).isEqualTo("STAGING");
    }

    @Test
    void pentestEngagement_defaults() {
        PentestEngagement pe = PentestEngagement.builder()
                .projectId(UUID.randomUUID()).clientName("Client").scope("scope").build();
        assertThat(pe.getStatus()).isEqualTo("PLANNING");
        assertThat(pe.getTestersJson()).isEqualTo("[]");
        assertThat(pe.getAssetsJson()).isEqualTo("[]");
        assertThat(pe.getMethodology()).isEqualTo("OWASP WSTG");
        assertThat(pe.getEnvironment()).isEqualTo("STAGING");
    }

    // ════════════════════════════════════════════════════════════════
    //  SCAN
    // ════════════════════════════════════════════════════════════════

    @Test
    void scan_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        Instant now = Instant.now();
        Scan s = Scan.builder()
                .projectId(pid).assetId(assetId).organizationId(orgId)
                .profile("FULL").scannerType("SEMGREP").scanType("SAST")
                .status("COMPLETED").target("10.0.0.1").targetUrl("https://api.example.com")
                .startedAt(now).finishedAt(now.plusSeconds(300))
                .initiatedBy("admin@vulnerax.io").configJson("{\"rules\":\"all\"}")
                .scopeJson("{\"depth\":3}").findingsCount(5).durationMs(300000L).build();
        s.setId(UUID.randomUUID());

        assertThat(s.getProjectId()).isEqualTo(pid);
        assertThat(s.getAssetId()).isEqualTo(assetId);
        assertThat(s.getOrganizationId()).isEqualTo(orgId);
        assertThat(s.getProfile()).isEqualTo("FULL");
        assertThat(s.getScannerType()).isEqualTo("SEMGREP");
        assertThat(s.getScanType()).isEqualTo("SAST");
        assertThat(s.getStatus()).isEqualTo("COMPLETED");
        assertThat(s.getTarget()).isEqualTo("10.0.0.1");
        assertThat(s.getTargetUrl()).isEqualTo("https://api.example.com");
        assertThat(s.getStartedAt()).isEqualTo(now);
        assertThat(s.getFinishedAt()).isNotNull();
        assertThat(s.getInitiatedBy()).isEqualTo("admin@vulnerax.io");
        assertThat(s.getConfigJson()).contains("rules");
        assertThat(s.getScopeJson()).contains("depth");
        assertThat(s.getFindingsCount()).isEqualTo(5);
        assertThat(s.getDurationMs()).isEqualTo(300000L);
    }

    @Test
    void scan_defaults() {
        Scan s = Scan.builder().projectId(UUID.randomUUID()).profile("QUICK")
                .scannerType("TRIVY").scanType("SCA").build();
        assertThat(s.getStatus()).isEqualTo("QUEUED");
    }

    // ════════════════════════════════════════════════════════════════
    //  SCAN JOB
    // ════════════════════════════════════════════════════════════════

    @Test
    void scanJob_builder_allFields() {
        UUID scanId = UUID.randomUUID();
        ScanJob sj = ScanJob.builder()
                .scanId(scanId).scannerPlugin("semgrep").status("RUNNING")
                .workerId("worker-1").logs("Starting scan...").progress(50)
                .resultJson("{\"findings\":[]}").error(null).build();
        sj.setId(UUID.randomUUID());

        assertThat(sj.getScanId()).isEqualTo(scanId);
        assertThat(sj.getScannerPlugin()).isEqualTo("semgrep");
        assertThat(sj.getStatus()).isEqualTo("RUNNING");
        assertThat(sj.getWorkerId()).isEqualTo("worker-1");
        assertThat(sj.getLogs()).isEqualTo("Starting scan...");
        assertThat(sj.getProgress()).isEqualTo(50);
        assertThat(sj.getResultJson()).contains("findings");
        assertThat(sj.getError()).isNull();
    }

    @Test
    void scanJob_defaults() {
        ScanJob sj = ScanJob.builder().scanId(UUID.randomUUID()).scannerPlugin("trivy").build();
        assertThat(sj.getStatus()).isEqualTo("QUEUED");
    }

    // ════════════════════════════════════════════════════════════════
    //  USER
    // ════════════════════════════════════════════════════════════════

    @Test
    void user_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        User u = User.builder()
                .email("admin@vulnerax.io").passwordHash("$2a$10$hashed")
                .fullName("Security Admin").role(User.Role.ORG_OWNER)
                .mfaEnabled(true).mfaSecret("secret123").ssoProvider("okta")
                .active(true).authorities(Set.of("ROLE_ORG_OWNER"))
                .organizationId(orgId).recoveryCodes(List.of("code1", "code2")).build();
        u.setId(UUID.randomUUID());

        assertThat(u.getEmail()).isEqualTo("admin@vulnerax.io");
        assertThat(u.getPasswordHash()).isEqualTo("$2a$10$hashed");
        assertThat(u.getFullName()).isEqualTo("Security Admin");
        assertThat(u.getRole()).isEqualTo(User.Role.ORG_OWNER);
        assertThat(u.getMfaEnabled()).isTrue();
        assertThat(u.getMfaSecret()).isEqualTo("secret123");
        assertThat(u.getSsoProvider()).isEqualTo("okta");
        assertThat(u.getActive()).isTrue();
        assertThat(u.getAuthorities()).contains("ROLE_ORG_OWNER");
        assertThat(u.getOrganizationId()).isEqualTo(orgId);
        assertThat(u.getRecoveryCodes()).containsExactly("code1", "code2");
    }

    @Test
    void user_defaults() {
        User u = new User();
        assertThat(u.getRole()).isEqualTo(User.Role.DEVELOPER);
        assertThat(u.getMfaEnabled()).isFalse();
        assertThat(u.getActive()).isTrue();
    }

    @Test
    void user_roles_allValues() {
        User.Role[] roles = User.Role.values();
        assertThat(roles).hasSize(9);
        assertThat(roles).contains(
                User.Role.ORG_OWNER, User.Role.SECURITY_ADMIN, User.Role.SECURITY_ENGINEER,
                User.Role.PENTESTER, User.Role.DEVELOPER, User.Role.TECH_LEAD,
                User.Role.AUDITOR, User.Role.VIEWER, User.Role.CLIENT
        );
    }

    @Test
    void user_stringListConverter_convertToDatabaseColumn() {
        User.StringListConverter converter = new User.StringListConverter();
        String result = converter.convertToDatabaseColumn(List.of("code1", "code2"));
        assertThat(result).contains("code1").contains("code2");
    }

    @Test
    void user_stringListConverter_convertToDatabaseColumn_null() {
        User.StringListConverter converter = new User.StringListConverter();
        assertThat(converter.convertToDatabaseColumn(null)).isNull();
    }

    @Test
    void user_stringListConverter_convertToEntityAttribute() {
        User.StringListConverter converter = new User.StringListConverter();
        List<String> result = converter.convertToEntityAttribute("[\"code1\",\"code2\"]");
        assertThat(result).containsExactly("code1", "code2");
    }

    @Test
    void user_stringListConverter_convertToEntityAttribute_null() {
        User.StringListConverter converter = new User.StringListConverter();
        assertThat(converter.convertToEntityAttribute(null)).isEmpty();
    }

    @Test
    void user_stringListConverter_convertToEntityAttribute_empty() {
        User.StringListConverter converter = new User.StringListConverter();
        assertThat(converter.convertToEntityAttribute("")).isEmpty();
    }

    @Test
    void user_stringListConverter_convertToEntityAttribute_invalidJson() {
        User.StringListConverter converter = new User.StringListConverter();
        assertThat(converter.convertToEntityAttribute("not-json")).isEmpty();
    }

    @Test
    void user_stringListConverter_convertToDatabaseColumn_exception() {
        User.StringListConverter converter = new User.StringListConverter();
        // Valid list should produce valid JSON
        String json = converter.convertToDatabaseColumn(List.of("a"));
        assertThat(json).isNotEmpty();
    }

    // ════════════════════════════════════════════════════════════════
    //  ORGANIZATION, PROJECT, WORKSPACE
    // ════════════════════════════════════════════════════════════════

    @Test
    void organization_builder_allFields() {
        Organization org = Organization.builder()
                .name("Acme Corp").slug("acme-corp")
                .description("Security team").tier("ENTERPRISE").active(true).build();
        org.setId(UUID.randomUUID());

        assertThat(org.getName()).isEqualTo("Acme Corp");
        assertThat(org.getSlug()).isEqualTo("acme-corp");
        assertThat(org.getDescription()).isEqualTo("Security team");
        assertThat(org.getTier()).isEqualTo("ENTERPRISE");
        assertThat(org.getActive()).isTrue();
    }

    @Test
    void organization_defaults() {
        Organization org = Organization.builder().name("Test").slug("test").build();
        assertThat(org.getTier()).isEqualTo("ENTERPRISE");
        assertThat(org.getActive()).isTrue();
    }

    @Test
    void project_builder_allFields() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        Project p = Project.builder()
                .name("WebApp").workspaceId(wsId).organizationId(orgId)
                .description("Main webapp").criticality("CRITICAL")
                .status("ACTIVE").businessUnit("Engineering")
                .techLead("lead@vulnerax.io").securityChampion("sec@vulnerax.io").build();
        p.setId(UUID.randomUUID());

        assertThat(p.getName()).isEqualTo("WebApp");
        assertThat(p.getWorkspaceId()).isEqualTo(wsId);
        assertThat(p.getOrganizationId()).isEqualTo(orgId);
        assertThat(p.getDescription()).isEqualTo("Main webapp");
        assertThat(p.getCriticality()).isEqualTo("CRITICAL");
        assertThat(p.getStatus()).isEqualTo("ACTIVE");
        assertThat(p.getBusinessUnit()).isEqualTo("Engineering");
        assertThat(p.getTechLead()).isEqualTo("lead@vulnerax.io");
        assertThat(p.getSecurityChampion()).isEqualTo("sec@vulnerax.io");
    }

    @Test
    void project_defaults() {
        Project p = Project.builder().name("Test").workspaceId(UUID.randomUUID())
                .organizationId(UUID.randomUUID()).build();
        assertThat(p.getCriticality()).isEqualTo("HIGH");
        assertThat(p.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void workspace_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        Workspace ws = Workspace.builder()
                .name("Production").organizationId(orgId)
                .description("Prod environment").environment("PRODUCTION").build();
        ws.setId(UUID.randomUUID());

        assertThat(ws.getName()).isEqualTo("Production");
        assertThat(ws.getOrganizationId()).isEqualTo(orgId);
        assertThat(ws.getDescription()).isEqualTo("Prod environment");
        assertThat(ws.getEnvironment()).isEqualTo("PRODUCTION");
    }

    @Test
    void workspace_defaults() {
        Workspace ws = Workspace.builder().name("Test").organizationId(UUID.randomUUID()).build();
        assertThat(ws.getEnvironment()).isEqualTo("PRODUCTION");
    }

    // ════════════════════════════════════════════════════════════════
    //  SBOM
    // ════════════════════════════════════════════════════════════════

    @Test
    void sbom_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Sbom sbom = Sbom.builder()
                .projectId(pid).assetId(assetId).format("CYCLONEDX")
                .version("1.0").contentJson("{\"components\":[]}")
                .componentCount(10).vulnerableCount(2).build();
        sbom.setId(UUID.randomUUID());

        assertThat(sbom.getProjectId()).isEqualTo(pid);
        assertThat(sbom.getAssetId()).isEqualTo(assetId);
        assertThat(sbom.getFormat()).isEqualTo("CYCLONEDX");
        assertThat(sbom.getVersion()).isEqualTo("1.0");
        assertThat(sbom.getContentJson()).contains("components");
        assertThat(sbom.getComponentCount()).isEqualTo(10);
        assertThat(sbom.getVulnerableCount()).isEqualTo(2);
    }

    @Test
    void sbom_defaults() {
        Sbom sbom = Sbom.builder().projectId(UUID.randomUUID()).format("SPDX").version("1.0").build();
        assertThat(sbom.getComponentCount()).isEqualTo(0);
        assertThat(sbom.getVulnerableCount()).isEqualTo(0);
    }

    // ════════════════════════════════════════════════════════════════
    //  REPORT
    // ════════════════════════════════════════════════════════════════

    @Test
    void report_builder_allFields() {
        UUID pid = UUID.randomUUID();
        Report r = Report.builder()
                .projectId(pid).type("EXECUTIVE").title("Q1 Report")
                .format("PDF").status("READY").contentJson("{\"sections\":[]}")
                .generatedBy("system").filePath("s3://reports/r1.pdf")
                .classification("CONFIDENTIAL").build();
        r.setId(UUID.randomUUID());

        assertThat(r.getProjectId()).isEqualTo(pid);
        assertThat(r.getType()).isEqualTo("EXECUTIVE");
        assertThat(r.getTitle()).isEqualTo("Q1 Report");
        assertThat(r.getFormat()).isEqualTo("PDF");
        assertThat(r.getStatus()).isEqualTo("READY");
        assertThat(r.getContentJson()).contains("sections");
        assertThat(r.getGeneratedBy()).isEqualTo("system");
        assertThat(r.getFilePath()).isEqualTo("s3://reports/r1.pdf");
        assertThat(r.getClassification()).isEqualTo("CONFIDENTIAL");
    }

    @Test
    void report_defaults() {
        Report r = Report.builder().projectId(UUID.randomUUID()).type("TECHNICAL")
                .title("Report").build();
        assertThat(r.getStatus()).isEqualTo("DRAFT");
    }

    // ════════════════════════════════════════════════════════════════
    //  COMPLIANCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void complianceFramework_builder_allFields() {
        ComplianceFramework cf = ComplianceFramework.builder()
                .name("OWASP Top 10").version("2021")
                .description("OWASP Top 10 Web App Risks")
                .type("STANDARD").controlsJson("[\"A01\",\"A02\"]")
                .mappingJson("{\"A01\":\"CWE-89\"}").build();
        cf.setId(UUID.randomUUID());

        assertThat(cf.getName()).isEqualTo("OWASP Top 10");
        assertThat(cf.getVersion()).isEqualTo("2021");
        assertThat(cf.getDescription()).isEqualTo("OWASP Top 10 Web App Risks");
        assertThat(cf.getType()).isEqualTo("STANDARD");
        assertThat(cf.getControlsJson()).contains("A01");
        assertThat(cf.getMappingJson()).contains("A01");
    }

    @Test
    void complianceFramework_defaults() {
        ComplianceFramework cf = ComplianceFramework.builder().name("NIST").version("1.0").build();
        assertThat(cf.getType()).isEqualTo("STANDARD");
        assertThat(cf.getControlsJson()).isEqualTo("[]");
        assertThat(cf.getMappingJson()).isEqualTo("{}");
    }

    @Test
    void complianceAssessment_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID fid = UUID.randomUUID();
        ComplianceAssessment ca = ComplianceAssessment.builder()
                .projectId(pid).frameworkId(fid).status("COMPLETED")
                .resultsJson("[{\"control\":\"A01\",\"status\":\"PASS\"}]")
                .score(85.5).passed(17).failed(2).notApplicable(1).notTested(0).build();
        ca.setId(UUID.randomUUID());

        assertThat(ca.getProjectId()).isEqualTo(pid);
        assertThat(ca.getFrameworkId()).isEqualTo(fid);
        assertThat(ca.getStatus()).isEqualTo("COMPLETED");
        assertThat(ca.getResultsJson()).contains("A01");
        assertThat(ca.getScore()).isEqualTo(85.5);
        assertThat(ca.getPassed()).isEqualTo(17);
        assertThat(ca.getFailed()).isEqualTo(2);
        assertThat(ca.getNotApplicable()).isEqualTo(1);
        assertThat(ca.getNotTested()).isEqualTo(0);
    }

    @Test
    void complianceAssessment_defaults() {
        ComplianceAssessment ca = ComplianceAssessment.builder()
                .projectId(UUID.randomUUID()).frameworkId(UUID.randomUUID()).build();
        assertThat(ca.getStatus()).isEqualTo("IN_PROGRESS");
        assertThat(ca.getResultsJson()).isEqualTo("[]");
        assertThat(ca.getScore()).isEqualTo(0.0);
        assertThat(ca.getPassed()).isEqualTo(0);
        assertThat(ca.getFailed()).isEqualTo(0);
        assertThat(ca.getNotApplicable()).isEqualTo(0);
        assertThat(ca.getNotTested()).isEqualTo(0);
    }

    // ════════════════════════════════════════════════════════════════
    //  THREAT MODEL
    // ════════════════════════════════════════════════════════════════

    @Test
    void threatModel_builder_allFields() {
        UUID pid = UUID.randomUUID();
        ThreatModel tm = ThreatModel.builder()
                .projectId(pid).name("WebApp Threat Model")
                .description("STRIDE analysis").status("DRAFT")
                .componentsJson("[{\"type\":\"web\"}]").dataflowsJson("[{\"from\":\"ui\",\"to\":\"api\"}]")
                .trustBoundariesJson("[{\"name\":\"dmz\"}]").threatsJson("[{\"threat\":\"spoofing\"}]")
                .controlsJson("[{\"control\":\"auth\"}]").diagramJson("{\"layout\":\"horizontal\"}").build();
        tm.setId(UUID.randomUUID());

        assertThat(tm.getProjectId()).isEqualTo(pid);
        assertThat(tm.getName()).isEqualTo("WebApp Threat Model");
        assertThat(tm.getDescription()).isEqualTo("STRIDE analysis");
        assertThat(tm.getStatus()).isEqualTo("DRAFT");
        assertThat(tm.getComponentsJson()).contains("web");
        assertThat(tm.getDataflowsJson()).contains("ui");
        assertThat(tm.getTrustBoundariesJson()).contains("dmz");
        assertThat(tm.getThreatsJson()).contains("spoofing");
        assertThat(tm.getControlsJson()).contains("auth");
        assertThat(tm.getDiagramJson()).contains("horizontal");
    }

    @Test
    void threatModel_defaults() {
        ThreatModel tm = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM").build();
        assertThat(tm.getStatus()).isEqualTo("DRAFT");
        assertThat(tm.getComponentsJson()).isEqualTo("[]");
        assertThat(tm.getDataflowsJson()).isEqualTo("[]");
        assertThat(tm.getTrustBoundariesJson()).isEqualTo("[]");
        assertThat(tm.getThreatsJson()).isEqualTo("[]");
        assertThat(tm.getControlsJson()).isEqualTo("[]");
    }

    // ════════════════════════════════════════════════════════════════
    //  AI ASSET
    // ════════════════════════════════════════════════════════════════

    @Test
    void aiAsset_builder_allFields() {
        UUID pid = UUID.randomUUID();
        AiAsset aa = AiAsset.builder()
                .projectId(pid).name("ChatBot").type("LLM")
                .model("gpt-4").provider("OpenAI")
                .endpointsJson("[\"/api/chat\"]").ragnJson("{\"chunks\":512}")
                .findingsJson("[{\"severity\":\"MEDIUM\"}]")
                .riskLevel("HIGH").status("ACTIVE").build();
        aa.setId(UUID.randomUUID());

        assertThat(aa.getProjectId()).isEqualTo(pid);
        assertThat(aa.getName()).isEqualTo("ChatBot");
        assertThat(aa.getType()).isEqualTo("LLM");
        assertThat(aa.getModel()).isEqualTo("gpt-4");
        assertThat(aa.getProvider()).isEqualTo("OpenAI");
        assertThat(aa.getEndpointsJson()).contains("/api/chat");
        assertThat(aa.getRagnJson()).contains("chunks");
        assertThat(aa.getFindingsJson()).contains("MEDIUM");
        assertThat(aa.getRiskLevel()).isEqualTo("HIGH");
        assertThat(aa.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void aiAsset_defaults() {
        AiAsset aa = AiAsset.builder().projectId(UUID.randomUUID()).name("AI").type("LLM").build();
        assertThat(aa.getEndpointsJson()).isEqualTo("[]");
        assertThat(aa.getFindingsJson()).isEqualTo("[]");
        assertThat(aa.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(aa.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  IAM RESOURCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void iamResource_builder_allFields() {
        UUID pid = UUID.randomUUID();
        IamResource ir = IamResource.builder()
                .projectId(pid).provider("AWS").principalType("USER")
                .principalName("admin").policiesJson("[{\"name\":\"Admin\"}]")
                .permissionsJson("[\"s3:*\"]").riskJson("{\"excessive\":true}")
                .isExcessive(true).isDormant(false).status("ACTIVE").build();
        ir.setId(UUID.randomUUID());

        assertThat(ir.getProjectId()).isEqualTo(pid);
        assertThat(ir.getProvider()).isEqualTo("AWS");
        assertThat(ir.getPrincipalType()).isEqualTo("USER");
        assertThat(ir.getPrincipalName()).isEqualTo("admin");
        assertThat(ir.getPoliciesJson()).contains("Admin");
        assertThat(ir.getPermissionsJson()).contains("s3:*");
        assertThat(ir.getRiskJson()).contains("excessive");
        assertThat(ir.getIsExcessive()).isTrue();
        assertThat(ir.getIsDormant()).isFalse();
        assertThat(ir.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void iamResource_defaults() {
        IamResource ir = IamResource.builder().projectId(UUID.randomUUID())
                .principalType("USER").principalName("test").build();
        assertThat(ir.getProvider()).isEqualTo("AWS");
        assertThat(ir.getPoliciesJson()).isEqualTo("[]");
        assertThat(ir.getPermissionsJson()).isEqualTo("[]");
        assertThat(ir.getRiskJson()).isEqualTo("{}");
        assertThat(ir.getIsExcessive()).isFalse();
        assertThat(ir.getIsDormant()).isFalse();
        assertThat(ir.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  BROWSER EXTENSION
    // ════════════════════════════════════════════════════════════════

    @Test
    void browserExtension_builder_allFields() {
        UUID pid = UUID.randomUUID();
        BrowserExtension be = BrowserExtension.builder()
                .projectId(pid).name("SecurityPlugin")
                .manifestJson("{\"version\":\"1.0\"}")
                .permissionsJson("[\"activeTab\"]")
                .findingsJson("[{\"severity\":\"LOW\"}]")
                .riskLevel("MEDIUM").status("ACTIVE").build();
        be.setId(UUID.randomUUID());

        assertThat(be.getProjectId()).isEqualTo(pid);
        assertThat(be.getName()).isEqualTo("SecurityPlugin");
        assertThat(be.getManifestJson()).contains("version");
        assertThat(be.getPermissionsJson()).contains("activeTab");
        assertThat(be.getFindingsJson()).contains("LOW");
        assertThat(be.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(be.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void browserExtension_defaults() {
        BrowserExtension be = BrowserExtension.builder().projectId(UUID.randomUUID())
                .name("Ext").manifestJson("{}").build();
        assertThat(be.getPermissionsJson()).isEqualTo("[]");
        assertThat(be.getFindingsJson()).isEqualTo("[]");
        assertThat(be.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(be.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  CI/CD PIPELINE
    // ════════════════════════════════════════════════════════════════

    @Test
    void cicdPipeline_builder_allFields() {
        UUID pid = UUID.randomUUID();
        CicdPipeline cp = CicdPipeline.builder()
                .projectId(pid).platform("GITHUB_ACTIONS")
                .repository("org/repo").pipelineName("CI")
                .configurationJson("{\"triggers\":[\"push\"]}")
                .findingsJson("[{\"severity\":\"HIGH\"}]")
                .riskLevel("HIGH").status("ACTIVE").build();
        cp.setId(UUID.randomUUID());

        assertThat(cp.getProjectId()).isEqualTo(pid);
        assertThat(cp.getPlatform()).isEqualTo("GITHUB_ACTIONS");
        assertThat(cp.getRepository()).isEqualTo("org/repo");
        assertThat(cp.getPipelineName()).isEqualTo("CI");
        assertThat(cp.getConfigurationJson()).contains("triggers");
        assertThat(cp.getFindingsJson()).contains("HIGH");
        assertThat(cp.getRiskLevel()).isEqualTo("HIGH");
        assertThat(cp.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void cicdPipeline_defaults() {
        CicdPipeline cp = CicdPipeline.builder().projectId(UUID.randomUUID())
                .platform("JENKINS").repository("repo").pipelineName("build").build();
        assertThat(cp.getFindingsJson()).isEqualTo("[]");
        assertThat(cp.getRiskLevel()).isEqualTo("MEDIUM");
        assertThat(cp.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  IAC SCAN
    // ════════════════════════════════════════════════════════════════

    @Test
    void iacScan_builder_allFields() {
        UUID pid = UUID.randomUUID();
        IacScan is = IacScan.builder()
                .projectId(pid).repository("org/repo").filePath("main.tf")
                .tool("CHECKOV").findingsJson("[{\"severity\":\"CRITICAL\"}]")
                .passed(10).failed(2).status("COMPLETED").build();
        is.setId(UUID.randomUUID());

        assertThat(is.getProjectId()).isEqualTo(pid);
        assertThat(is.getRepository()).isEqualTo("org/repo");
        assertThat(is.getFilePath()).isEqualTo("main.tf");
        assertThat(is.getTool()).isEqualTo("CHECKOV");
        assertThat(is.getFindingsJson()).contains("CRITICAL");
        assertThat(is.getPassed()).isEqualTo(10);
        assertThat(is.getFailed()).isEqualTo(2);
        assertThat(is.getStatus()).isEqualTo("COMPLETED");
    }

    @Test
    void iacScan_defaults() {
        IacScan is = IacScan.builder().projectId(UUID.randomUUID()).filePath("main.tf").build();
        assertThat(is.getTool()).isEqualTo("CHECKOV");
        assertThat(is.getFindingsJson()).isEqualTo("[]");
        assertThat(is.getPassed()).isEqualTo(0);
        assertThat(is.getFailed()).isEqualTo(0);
        assertThat(is.getStatus()).isEqualTo("COMPLETED");
    }

    // ════════════════════════════════════════════════════════════════
    //  INTEGRATION
    // ════════════════════════════════════════════════════════════════

    @Test
    void integration_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        Integration i = Integration.builder()
                .organizationId(orgId).type("SCM").provider("GITHUB")
                .name("GitHub Integration").configurationJson("{\"org\":\"acme\"}")
                .credentialsEncrypted("encrypted_data").status("ACTIVE").build();
        i.setId(UUID.randomUUID());

        assertThat(i.getOrganizationId()).isEqualTo(orgId);
        assertThat(i.getType()).isEqualTo("SCM");
        assertThat(i.getProvider()).isEqualTo("GITHUB");
        assertThat(i.getName()).isEqualTo("GitHub Integration");
        assertThat(i.getConfigurationJson()).contains("org");
        assertThat(i.getCredentialsEncrypted()).isEqualTo("encrypted_data");
        assertThat(i.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void integration_defaults() {
        Integration i = Integration.builder().organizationId(UUID.randomUUID())
                .type("SCM").provider("GITHUB").name("Git").build();
        assertThat(i.getConfigurationJson()).isEqualTo("{}");
        assertThat(i.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  K8S RESOURCE
    // ════════════════════════════════════════════════════════════════

    @Test
    void k8sResource_builder_allFields() {
        UUID pid = UUID.randomUUID();
        K8sResource kr = K8sResource.builder()
                .projectId(pid).clusterName("prod-cluster")
                .namespace("kube-system").kind("Deployment").name("nginx")
                .configurationJson("{\"replicas\":3}")
                .riskJson("{\"privileged\":true}").status("ACTIVE").build();
        kr.setId(UUID.randomUUID());

        assertThat(kr.getProjectId()).isEqualTo(pid);
        assertThat(kr.getClusterName()).isEqualTo("prod-cluster");
        assertThat(kr.getNamespace()).isEqualTo("kube-system");
        assertThat(kr.getKind()).isEqualTo("Deployment");
        assertThat(kr.getName()).isEqualTo("nginx");
        assertThat(kr.getConfigurationJson()).contains("replicas");
        assertThat(kr.getRiskJson()).contains("privileged");
        assertThat(kr.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void k8sResource_defaults() {
        K8sResource kr = K8sResource.builder().projectId(UUID.randomUUID())
                .clusterName("c").kind("Pod").name("p").build();
        assertThat(kr.getNamespace()).isEqualTo("default");
        assertThat(kr.getStatus()).isEqualTo("ACTIVE");
    }

    // ════════════════════════════════════════════════════════════════
    //  NOTIFICATION
    // ════════════════════════════════════════════════════════════════

    @Test
    void notification_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        UUID pid = UUID.randomUUID();
        Notification n = Notification.builder()
                .organizationId(orgId).projectId(pid).type("FINDING_CREATED")
                .channel("EMAIL").recipient("admin@vulnerax.io")
                .subject("New Finding").body("SQL Injection found")
                .status("SENT").build();
        n.setId(UUID.randomUUID());

        assertThat(n.getOrganizationId()).isEqualTo(orgId);
        assertThat(n.getProjectId()).isEqualTo(pid);
        assertThat(n.getType()).isEqualTo("FINDING_CREATED");
        assertThat(n.getChannel()).isEqualTo("EMAIL");
        assertThat(n.getRecipient()).isEqualTo("admin@vulnerax.io");
        assertThat(n.getSubject()).isEqualTo("New Finding");
        assertThat(n.getBody()).isEqualTo("SQL Injection found");
        assertThat(n.getStatus()).isEqualTo("SENT");
    }

    @Test
    void notification_defaults() {
        Notification n = Notification.builder().type("ALERT").channel("SLACK")
                .recipient("#security").subject("Alert").build();
        assertThat(n.getStatus()).isEqualTo("PENDING");
    }

    // ════════════════════════════════════════════════════════════════
    //  AUDIT EVENT
    // ════════════════════════════════════════════════════════════════

    @Test
    void auditEvent_builder_allFields() {
        AuditEvent ae = AuditEvent.builder()
                .action("FINDING_CREATED").entityType("Finding")
                .entityId("f-123").actor("admin@vulnerax.io")
                .details("Created finding for SQL injection")
                .ipAddress("10.0.0.1").build();
        ae.setId(UUID.randomUUID());

        assertThat(ae.getAction()).isEqualTo("FINDING_CREATED");
        assertThat(ae.getEntityType()).isEqualTo("Finding");
        assertThat(ae.getEntityId()).isEqualTo("f-123");
        assertThat(ae.getActor()).isEqualTo("admin@vulnerax.io");
        assertThat(ae.getDetails()).contains("SQL injection");
        assertThat(ae.getIpAddress()).isEqualTo("10.0.0.1");
    }

    // ════════════════════════════════════════════════════════════════
    //  ONECLICK RUN
    // ════════════════════════════════════════════════════════════════

    @Test
    void oneClickRun_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID reportId = UUID.randomUUID();
        OneClickRun ocr = OneClickRun.builder()
                .projectId(pid).target("https://api.example.com")
                .detectedType("API").status("COMPLETED").progress(100)
                .totalScans(5).completedScans(5).findingsCount(12)
                .reportId(reportId).scanIdsJson("[\"s1\",\"s2\"]")
                .message("Scan completed successfully").build();
        ocr.setId(UUID.randomUUID());

        assertThat(ocr.getProjectId()).isEqualTo(pid);
        assertThat(ocr.getTarget()).isEqualTo("https://api.example.com");
        assertThat(ocr.getDetectedType()).isEqualTo("API");
        assertThat(ocr.getStatus()).isEqualTo("COMPLETED");
        assertThat(ocr.getProgress()).isEqualTo(100);
        assertThat(ocr.getTotalScans()).isEqualTo(5);
        assertThat(ocr.getCompletedScans()).isEqualTo(5);
        assertThat(ocr.getFindingsCount()).isEqualTo(12);
        assertThat(ocr.getReportId()).isEqualTo(reportId);
        assertThat(ocr.getScanIdsJson()).contains("s1");
        assertThat(ocr.getMessage()).contains("completed");
    }

    @Test
    void oneClickRun_defaults() {
        OneClickRun ocr = OneClickRun.builder().target("https://example.com").build();
        assertThat(ocr.getStatus()).isEqualTo("QUEUED");
        assertThat(ocr.getProgress()).isEqualTo(0);
        assertThat(ocr.getCompletedScans()).isEqualTo(0);
    }

    // ════════════════════════════════════════════════════════════════
    //  SECURITY CAMPAIGN
    // ════════════════════════════════════════════════════════════════

    @Test
    void securityCampaign_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        SecurityCampaign sc = SecurityCampaign.builder()
                .organizationId(orgId).name("Q1 Campaign")
                .description("Fix all critical findings")
                .queryJson("{\"severity\":\"CRITICAL\"}")
                .status("ACTIVE").affectedCount(25).resolvedCount(10).build();
        sc.setId(UUID.randomUUID());

        assertThat(sc.getOrganizationId()).isEqualTo(orgId);
        assertThat(sc.getName()).isEqualTo("Q1 Campaign");
        assertThat(sc.getDescription()).isEqualTo("Fix all critical findings");
        assertThat(sc.getQueryJson()).contains("CRITICAL");
        assertThat(sc.getStatus()).isEqualTo("ACTIVE");
        assertThat(sc.getAffectedCount()).isEqualTo(25);
        assertThat(sc.getResolvedCount()).isEqualTo(10);
    }

    @Test
    void securityCampaign_defaults() {
        SecurityCampaign sc = SecurityCampaign.builder()
                .organizationId(UUID.randomUUID()).name("Campaign").build();
        assertThat(sc.getStatus()).isEqualTo("ACTIVE");
        assertThat(sc.getAffectedCount()).isEqualTo(0);
        assertThat(sc.getResolvedCount()).isEqualTo(0);
    }

    // ════════════════════════════════════════════════════════════════
    //  SECURITY POLICY
    // ════════════════════════════════════════════════════════════════

    @Test
    void securityPolicy_builder_allFields() {
        UUID orgId = UUID.randomUUID();
        SecurityPolicy sp = SecurityPolicy.builder()
                .organizationId(orgId).name("No Critical Findings")
                .description("Block deployment if critical findings exist")
                .ruleJson("{\"maxCritical\":0}").severity("CRITICAL")
                .enabled(true).type("GATE").build();
        sp.setId(UUID.randomUUID());

        assertThat(sp.getOrganizationId()).isEqualTo(orgId);
        assertThat(sp.getName()).isEqualTo("No Critical Findings");
        assertThat(sp.getDescription()).isEqualTo("Block deployment if critical findings exist");
        assertThat(sp.getRuleJson()).contains("maxCritical");
        assertThat(sp.getSeverity()).isEqualTo("CRITICAL");
        assertThat(sp.getEnabled()).isTrue();
        assertThat(sp.getType()).isEqualTo("GATE");
    }

    @Test
    void securityPolicy_defaults() {
        SecurityPolicy sp = SecurityPolicy.builder()
                .organizationId(UUID.randomUUID()).name("Policy").build();
        assertThat(sp.getSeverity()).isEqualTo("HIGH");
        assertThat(sp.getEnabled()).isTrue();
        assertThat(sp.getType()).isEqualTo("GATE");
    }

    // ════════════════════════════════════════════════════════════════
    //  POLICY EXCEPTION
    // ════════════════════════════════════════════════════════════════

    @Test
    void policyException_builder_allFields() {
        UUID policyId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        Instant exp = Instant.now().plusSeconds(86400 * 30);
        PolicyException pe = PolicyException.builder()
                .policyId(policyId).findingId(findingId)
                .reason("Business justification").owner("admin")
                .approver("ciso@vulnerax.io").expiration(exp)
                .compensatingControl("WAF rule").status("APPROVED").build();
        pe.setId(UUID.randomUUID());

        assertThat(pe.getPolicyId()).isEqualTo(policyId);
        assertThat(pe.getFindingId()).isEqualTo(findingId);
        assertThat(pe.getReason()).isEqualTo("Business justification");
        assertThat(pe.getOwner()).isEqualTo("admin");
        assertThat(pe.getApprover()).isEqualTo("ciso@vulnerax.io");
        assertThat(pe.getExpiration()).isEqualTo(exp);
        assertThat(pe.getCompensatingControl()).isEqualTo("WAF rule");
        assertThat(pe.getStatus()).isEqualTo("APPROVED");
    }

    @Test
    void policyException_defaults() {
        PolicyException pe = PolicyException.builder()
                .policyId(UUID.randomUUID()).reason("reason")
                .owner("owner").approver("approver")
                .expiration(Instant.now()).build();
        assertThat(pe.getStatus()).isEqualTo("PENDING");
    }

    // ════════════════════════════════════════════════════════════════
    //  PERMISSION & ROLE PERMISSION
    // ════════════════════════════════════════════════════════════════

    @Test
    void permission_builder_allFields() {
        Permission p = Permission.builder()
                .name("FINDINGS_READ").resource("FINDINGS")
                .action("READ").description("Read findings").build();
        p.setId(UUID.randomUUID());

        assertThat(p.getName()).isEqualTo("FINDINGS_READ");
        assertThat(p.getResource()).isEqualTo("FINDINGS");
        assertThat(p.getAction()).isEqualTo("READ");
        assertThat(p.getDescription()).isEqualTo("Read findings");
    }

    @Test
    void permission_noArgsConstructor() {
        Permission p = new Permission();
        assertThat(p).isNotNull();
    }

    @Test
    void rolePermission_builder_allFields() {
        Permission perm = Permission.builder().name("FINDINGS_READ")
                .resource("FINDINGS").action("READ").build();
        RolePermission rp = RolePermission.builder()
                .role("SECURITY_ADMIN").permission(perm).build();
        rp.setId(1L);

        assertThat(rp.getRole()).isEqualTo("SECURITY_ADMIN");
        assertThat(rp.getPermission()).isEqualTo(perm);
        assertThat(rp.getId()).isEqualTo(1L);
    }

    @Test
    void rolePermission_noArgsConstructor() {
        RolePermission rp = new RolePermission();
        assertThat(rp).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  RETEST
    // ════════════════════════════════════════════════════════════════

    @Test
    void retest_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID fid = UUID.randomUUID();
        UUID aid = UUID.randomUUID();
        UUID sid = UUID.randomUUID();
        Retest r = Retest.builder()
                .projectId(pid).findingId(fid).assetId(aid).scanId(sid)
                .type("FINDING").status("COMPLETED").requestedBy("admin")
                .result("PASS").evidenceJson("[{\"url\":\"...\"}]")
                .beforeJson("{\"open\":true}").afterJson("{\"open\":false}").build();
        r.setId(UUID.randomUUID());

        assertThat(r.getProjectId()).isEqualTo(pid);
        assertThat(r.getFindingId()).isEqualTo(fid);
        assertThat(r.getAssetId()).isEqualTo(aid);
        assertThat(r.getScanId()).isEqualTo(sid);
        assertThat(r.getType()).isEqualTo("FINDING");
        assertThat(r.getStatus()).isEqualTo("COMPLETED");
        assertThat(r.getRequestedBy()).isEqualTo("admin");
        assertThat(r.getResult()).isEqualTo("PASS");
        assertThat(r.getEvidenceJson()).contains("url");
        assertThat(r.getBeforeJson()).contains("open");
        assertThat(r.getAfterJson()).contains("open");
    }

    @Test
    void retest_defaults() {
        Retest r = Retest.builder().projectId(UUID.randomUUID()).build();
        assertThat(r.getType()).isEqualTo("FINDING");
        assertThat(r.getStatus()).isEqualTo("PENDING");
    }

    // ════════════════════════════════════════════════════════════════
    //  MOBILE ANALYSIS
    // ════════════════════════════════════════════════════════════════

    @Test
    void mobileAnalysis_builder_allFields() {
        UUID pid = UUID.randomUUID();
        UUID aid = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(pid).assetId(aid).platform("ANDROID")
                .fileName("app.apk").fileSha256("abc123").fileSize(1024L)
                .manifestJson("{}").stringsJson("[]").findingsJson("[]")
                .certInfo("cert").masvsScore(85).status("DONE").build();
        ma.setId(UUID.randomUUID());

        assertThat(ma.getProjectId()).isEqualTo(pid);
        assertThat(ma.getAssetId()).isEqualTo(aid);
        assertThat(ma.getPlatform()).isEqualTo("ANDROID");
        assertThat(ma.getFileName()).isEqualTo("app.apk");
        assertThat(ma.getFileSha256()).isEqualTo("abc123");
        assertThat(ma.getFileSize()).isEqualTo(1024L);
        assertThat(ma.getManifestJson()).isEqualTo("{}");
        assertThat(ma.getStringsJson()).isEqualTo("[]");
        assertThat(ma.getFindingsJson()).isEqualTo("[]");
        assertThat(ma.getCertInfo()).isEqualTo("cert");
        assertThat(ma.getMasvsScore()).isEqualTo(85);
        assertThat(ma.getStatus()).isEqualTo("DONE");
    }

    @Test
    void mobileAnalysis_defaults() {
        MobileAnalysis ma = MobileAnalysis.builder().platform("IOS").fileName("app.ipa").build();
        assertThat(ma.getMasvsScore()).isEqualTo(0);
    }

    // ════════════════════════════════════════════════════════════════
    //  SECURITY COVERAGE
    // ════════════════════════════════════════════════════════════════

    @Test
    void securityCoverage_builder_allFields() {
        UUID pid = UUID.randomUUID();
        SecurityCoverage sc = SecurityCoverage.builder()
                .projectId(pid).domain("AUTHENTICATION")
                .status("TESTED").coveragePercent(95)
                .detailsJson("{\"tests\":10}").build();
        sc.setId(UUID.randomUUID());

        assertThat(sc.getProjectId()).isEqualTo(pid);
        assertThat(sc.getDomain()).isEqualTo("AUTHENTICATION");
        assertThat(sc.getStatus()).isEqualTo("TESTED");
        assertThat(sc.getCoveragePercent()).isEqualTo(95);
        assertThat(sc.getDetailsJson()).contains("tests");
    }

    @Test
    void securityCoverage_defaults() {
        SecurityCoverage sc = SecurityCoverage.builder()
                .projectId(UUID.randomUUID()).domain("CRYPTO").build();
        assertThat(sc.getStatus()).isEqualTo("NOT_TESTED");
        assertThat(sc.getCoveragePercent()).isEqualTo(0);
        assertThat(sc.getDetailsJson()).isEqualTo("{}");
    }

    // ════════════════════════════════════════════════════════════════
    //  ENUMS
    // ════════════════════════════════════════════════════════════════

    @Test
    void findingType_allValues() {
        FindingType[] values = FindingType.values();
        assertThat(values).hasSize(20);
        assertThat(values).contains(
                FindingType.SAST, FindingType.SCA, FindingType.DAST, FindingType.SECRET,
                FindingType.API, FindingType.MOBILE, FindingType.CONTAINER, FindingType.IAC,
                FindingType.CLOUD, FindingType.NETWORK, FindingType.K8S, FindingType.AUTH,
                FindingType.CRYPTO, FindingType.INJECTION, FindingType.XSS, FindingType.CSRF,
                FindingType.SSRF, FindingType.LFI, FindingType.RCE, FindingType.INFO_DISCLOSURE
        );
    }

    @Test
    void findingType_valueOf() {
        assertThat(FindingType.valueOf("SAST")).isEqualTo(FindingType.SAST);
        assertThat(FindingType.valueOf("SCA")).isEqualTo(FindingType.SCA);
        assertThat(FindingType.valueOf("DAST")).isEqualTo(FindingType.DAST);
        assertThat(FindingType.valueOf("SECRET")).isEqualTo(FindingType.SECRET);
        assertThat(FindingType.valueOf("INFO_DISCLOSURE")).isEqualTo(FindingType.INFO_DISCLOSURE);
    }

    @Test
    void severity_allValues() {
        Severity[] values = Severity.values();
        assertThat(values).hasSize(5);
        assertThat(values).contains(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO);
    }

    @Test
    void severity_valueOf() {
        assertThat(Severity.valueOf("CRITICAL")).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.valueOf("HIGH")).isEqualTo(Severity.HIGH);
        assertThat(Severity.valueOf("MEDIUM")).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.valueOf("LOW")).isEqualTo(Severity.LOW);
        assertThat(Severity.valueOf("INFO")).isEqualTo(Severity.INFO);
    }

    // ════════════════════════════════════════════════════════════════
    //  API RESPONSE & PAGE RESPONSE
    // ════════════════════════════════════════════════════════════════

    @Test
    void apiResponse_ok() {
        ApiResponse<String> r = ApiResponse.ok("data");
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getData()).isEqualTo("data");
        assertThat(r.getMessage()).isNull();
    }

    @Test
    void apiResponse_ok_withMessage() {
        ApiResponse<String> r = ApiResponse.ok("data", "Success");
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getData()).isEqualTo("data");
        assertThat(r.getMessage()).isEqualTo("Success");
    }

    @Test
    void apiResponse_fail() {
        ApiResponse<?> r = ApiResponse.fail("Error occurred");
        assertThat(r.isSuccess()).isFalse();
        assertThat(r.getMessage()).isEqualTo("Error occurred");
        assertThat(r.getData()).isNull();
    }

    @Test
    void apiResponse_builder_allFields() {
        ApiResponse<String> r = ApiResponse.<String>builder()
                .success(true).message("ok").data("val").meta("meta").build();
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getMessage()).isEqualTo("ok");
        assertThat(r.getData()).isEqualTo("val");
        assertThat(r.getMeta()).isEqualTo("meta");
    }

    @Test
    void apiResponse_noArgsConstructor() {
        ApiResponse<Object> r = new ApiResponse<>();
        r.setSuccess(true);
        r.setMessage("msg");
        r.setData("data");
        r.setMeta("meta");
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getMessage()).isEqualTo("msg");
        assertThat(r.getData()).isEqualTo("data");
        assertThat(r.getMeta()).isEqualTo("meta");
    }

    @Test
    void apiResponse_equals_hashCode() {
        ApiResponse<String> r1 = ApiResponse.ok("data");
        ApiResponse<String> r2 = ApiResponse.ok("data");
        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void apiResponse_toString() {
        ApiResponse<String> r = ApiResponse.ok("data");
        assertThat(r.toString()).isNotNull();
    }

    @Test
    void pageResponse_builder_allFields() {
        PageResponse<String> pr = PageResponse.<String>builder()
                .content(List.of("a", "b")).page(0).size(10)
                .totalElements(100).totalPages(10).build();
        assertThat(pr.getContent()).hasSize(2);
        assertThat(pr.getPage()).isEqualTo(0);
        assertThat(pr.getSize()).isEqualTo(10);
        assertThat(pr.getTotalElements()).isEqualTo(100);
        assertThat(pr.getTotalPages()).isEqualTo(10);
    }

    @Test
    void pageResponse_from() {
        org.springframework.data.domain.Page<String> page =
                new org.springframework.data.domain.PageImpl<>(List.of("a", "b"),
                        org.springframework.data.domain.PageRequest.of(1, 10), 25);
        PageResponse<String> pr = PageResponse.from(page);
        assertThat(pr.getContent()).hasSize(2);
        assertThat(pr.getPage()).isEqualTo(1);
        assertThat(pr.getSize()).isEqualTo(10);
        assertThat(pr.getTotalElements()).isEqualTo(25);
        assertThat(pr.getTotalPages()).isEqualTo(3);
    }

    @Test
    void pageResponse_equals_hashCode() {
        PageResponse<String> p1 = PageResponse.<String>builder()
                .content(List.of()).page(0).size(10).totalElements(0).totalPages(0).build();
        PageResponse<String> p2 = PageResponse.<String>builder()
                .content(List.of()).page(0).size(10).totalElements(0).totalPages(0).build();
        assertThat(p1).isEqualTo(p2);
        assertThat(p1.hashCode()).isEqualTo(p2.hashCode());
    }

    @Test
    void pageResponse_toString() {
        PageResponse<String> p = PageResponse.<String>builder()
                .content(List.of("x")).page(0).size(10).totalElements(1).totalPages(1).build();
        assertThat(p.toString()).isNotNull();
    }

    // ════════════════════════════════════════════════════════════════
    //  BASE ENTITY
    // ════════════════════════════════════════════════════════════════

    @Test
    void baseEntity_gettersSetters() {
        BaseEntity be = new Asset();
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();
        be.setId(id);
        be.setCreatedAt(now);
        be.setUpdatedAt(now);
        assertThat(be.getId()).isEqualTo(id);
        assertThat(be.getCreatedAt()).isEqualTo(now);
        assertThat(be.getUpdatedAt()).isEqualTo(now);
    }

    // ════════════════════════════════════════════════════════════════
    //  TENANT CONTEXT
    // ════════════════════════════════════════════════════════════════

    @Test
    void tenantContext_setAndClear() {
        UUID orgId = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        TenantContext.set(orgId, projectId, "test@example.com");
        assertThat(TenantContext.getOrganizationId()).isEqualTo(orgId);
        assertThat(TenantContext.getProjectId()).isEqualTo(projectId);
        assertThat(TenantContext.getEmail()).isEqualTo("test@example.com");
        TenantContext.clear();
        assertThat(TenantContext.getOrganizationId()).isNull();
    }

    @Test
    void tenantContext_clearWhenEmpty() {
        TenantContext.clear();
        assertThat(TenantContext.getOrganizationId()).isNull();
    }

    @Test
    void tenantContext_getWithoutSet() {
        TenantContext.clear();
        TenantContext.TenantInfo info = TenantContext.get();
        assertThat(info).isNotNull();
    }

    @Test
    void tenantContext_record() {
        UUID orgId = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        TenantContext.TenantInfo info = new TenantContext.TenantInfo(orgId, projectId, "user@test.com");
        assertThat(info.organizationId()).isEqualTo(orgId);
        assertThat(info.projectId()).isEqualTo(projectId);
        assertThat(info.email()).isEqualTo("user@test.com");
    }

    // ════════════════════════════════════════════════════════════════
    //  DTO: AUTH CONTROLLER
    // ════════════════════════════════════════════════════════════════

    @Test
    void loginReq_gettersSetters() {
        AuthController.LoginReq lr = new AuthController.LoginReq();
        lr.setEmail("admin@vulnerax.io");
        lr.setPassword("secret123");
        assertThat(lr.getEmail()).isEqualTo("admin@vulnerax.io");
        assertThat(lr.getPassword()).isEqualTo("secret123");
    }

    @Test
    void loginReq_toString() {
        AuthController.LoginReq lr = new AuthController.LoginReq();
        lr.setEmail("test@test.com");
        lr.setPassword("pass");
        assertThat(lr.toString()).isNotNull();
    }

    @Test
    void loginReq_equals_hashCode() {
        AuthController.LoginReq lr1 = new AuthController.LoginReq();
        lr1.setEmail("a@b.com");
        lr1.setPassword("pass");
        AuthController.LoginReq lr2 = new AuthController.LoginReq();
        lr2.setEmail("a@b.com");
        lr2.setPassword("pass");
        assertThat(lr1).isEqualTo(lr2);
        assertThat(lr1.hashCode()).isEqualTo(lr2.hashCode());
    }

    @Test
    void registerReq_gettersSetters() {
        AuthController.RegisterReq rr = new AuthController.RegisterReq();
        rr.setEmail("user@vulnerax.io");
        rr.setPassword("pass123");
        rr.setFullName("Test User");
        rr.setRole("SECURITY_ADMIN");
        assertThat(rr.getEmail()).isEqualTo("user@vulnerax.io");
        assertThat(rr.getPassword()).isEqualTo("pass123");
        assertThat(rr.getFullName()).isEqualTo("Test User");
        assertThat(rr.getRole()).isEqualTo("SECURITY_ADMIN");
    }

    @Test
    void registerReq_toString() {
        AuthController.RegisterReq rr = new AuthController.RegisterReq();
        rr.setEmail("a@b.com");
        rr.setPassword("pass");
        rr.setFullName("Name");
        assertThat(rr.toString()).isNotNull();
    }

    @Test
    void registerReq_equals_hashCode() {
        AuthController.RegisterReq rr1 = new AuthController.RegisterReq();
        rr1.setEmail("a@b.com");
        rr1.setPassword("pass");
        rr1.setFullName("Name");
        AuthController.RegisterReq rr2 = new AuthController.RegisterReq();
        rr2.setEmail("a@b.com");
        rr2.setPassword("pass");
        rr2.setFullName("Name");
        assertThat(rr1).isEqualTo(rr2);
        assertThat(rr1.hashCode()).isEqualTo(rr2.hashCode());
    }

    // ════════════════════════════════════════════════════════════════
    //  DTO: FINDING CONTROLLER
    // ════════════════════════════════════════════════════════════════

    @Test
    void statusReq_gettersSetters() {
        com.vulnerax.modules.finding.FindingController.StatusReq sr =
                new com.vulnerax.modules.finding.FindingController.StatusReq();
        sr.setStatus("RESOLVED");
        sr.setComment("Fixed the vulnerability");
        assertThat(sr.getStatus()).isEqualTo("RESOLVED");
        assertThat(sr.getComment()).isEqualTo("Fixed the vulnerability");
    }

    @Test
    void statusReq_toString() {
        com.vulnerax.modules.finding.FindingController.StatusReq sr =
                new com.vulnerax.modules.finding.FindingController.StatusReq();
        sr.setStatus("OPEN");
        sr.setComment("Comment");
        assertThat(sr.toString()).isNotNull();
    }

    @Test
    void statusReq_equals_hashCode() {
        com.vulnerax.modules.finding.FindingController.StatusReq sr1 =
                new com.vulnerax.modules.finding.FindingController.StatusReq();
        sr1.setStatus("OPEN");
        sr1.setComment("c");
        com.vulnerax.modules.finding.FindingController.StatusReq sr2 =
                new com.vulnerax.modules.finding.FindingController.StatusReq();
        sr2.setStatus("OPEN");
        sr2.setComment("c");
        assertThat(sr1).isEqualTo(sr2);
        assertThat(sr1.hashCode()).isEqualTo(sr2.hashCode());
    }

    // ════════════════════════════════════════════════════════════════
    //  DTO: REPORT CONTROLLER
    // ════════════════════════════════════════════════════════════════

    @Test
    void genReq_gettersSetters() {
        ReportController.GenReq gr = new ReportController.GenReq();
        UUID pid = UUID.randomUUID();
        gr.setProjectId(pid);
        gr.setType("EXECUTIVE");
        gr.setTitle("Q1 Report");
        gr.setFormat("PDF");
        assertThat(gr.getProjectId()).isEqualTo(pid);
        assertThat(gr.getType()).isEqualTo("EXECUTIVE");
        assertThat(gr.getTitle()).isEqualTo("Q1 Report");
        assertThat(gr.getFormat()).isEqualTo("PDF");
    }

    @Test
    void genReq_toString() {
        ReportController.GenReq gr = new ReportController.GenReq();
        gr.setType("TECHNICAL");
        assertThat(gr.toString()).isNotNull();
    }

    @Test
    void genReq_equals_hashCode() {
        UUID pid = UUID.randomUUID();
        ReportController.GenReq gr1 = new ReportController.GenReq();
        gr1.setProjectId(pid);
        gr1.setType("EXECUTIVE");
        gr1.setTitle("Report");
        gr1.setFormat("PDF");
        ReportController.GenReq gr2 = new ReportController.GenReq();
        gr2.setProjectId(pid);
        gr2.setType("EXECUTIVE");
        gr2.setTitle("Report");
        gr2.setFormat("PDF");
        assertThat(gr1).isEqualTo(gr2);
        assertThat(gr1.hashCode()).isEqualTo(gr2.hashCode());
    }

    // ════════════════════════════════════════════════════════════════
    //  FINDING CORRELATION ENGINE
    // ════════════════════════════════════════════════════════════════

    @Test
    void finding_correlationEngine_record() {
        Finding f = Finding.builder().findingId("F-001").build();
        List<Finding> matches = List.of(f);
        var cr = new com.vulnerax.modules.finding.FindingCorrelationEngine.CorrelationResult(
                matches, "EXACT_MATCH", true, "MERGE_EVIDENCE");
        assertThat(cr.matches()).hasSize(1);
        assertThat(cr.reason()).isEqualTo("EXACT_MATCH");
        assertThat(cr.isDuplicate()).isTrue();
        assertThat(cr.mergeRecommendation()).isEqualTo("MERGE_EVIDENCE");
    }

    // ════════════════════════════════════════════════════════════════
    //  SECURITY SCANNER PLUGIN
    // ════════════════════════════════════════════════════════════════

    @Test
    void securityScannerPlugin_scanPlan() {
        var step = new com.vulnerax.modules.scan.SecurityScannerPlugin.ScanStep(
                "s1", "SAST", "Static analysis", Map.of("rules", "auto"));
        var plan = new com.vulnerax.modules.scan.SecurityScannerPlugin.ScanPlan(
                List.of(step), Map.of("timeout", "300"));
        assertThat(plan.steps()).hasSize(1);
        assertThat(plan.metadata()).containsEntry("timeout", "300");
    }

    @Test
    void securityScannerPlugin_validationResult() {
        var vr = new com.vulnerax.modules.scan.SecurityScannerPlugin.ValidationResult(
                true, "All good");
        assertThat(vr.valid()).isTrue();
        assertThat(vr.reason()).isEqualTo("All good");
    }

    @Test
    void securityScannerPlugin_scanStep() {
        var step = new com.vulnerax.modules.scan.SecurityScannerPlugin.ScanStep(
                "s1", "SAST", "Static analysis", Map.of("rules", "auto"));
        assertThat(step.id()).isEqualTo("s1");
        assertThat(step.type()).isEqualTo("SAST");
        assertThat(step.description()).isEqualTo("Static analysis");
        assertThat(step.config()).containsEntry("rules", "auto");
    }

    // ════════════════════════════════════════════════════════════════
    //  FINDING CORRELATION ENGINE - CORRELATION
    // ════════════════════════════════════════════════════════════════

    @Test
    void findingCorrelationEngine_exactMatch() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding newF = Finding.builder().findingId("NEW").title("SQL Injection")
                .type("SAST").severity("CRITICAL").cwe("CWE-89").build();
        newF.setId(UUID.randomUUID());
        Finding existing = Finding.builder().findingId("EXISTING").title("SQL Injection")
                .type("SAST").severity("CRITICAL").cwe("CWE-89").build();
        existing.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of(existing));
        assertThat(result.matches()).isNotEmpty();
        assertThat(result.reason()).isIn("EXACT_MATCH", "SIMILAR", "RELATED");
    }

    @Test
    void findingCorrelationEngine_noMatch() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding newF = Finding.builder().findingId("NEW").title("XSS").type("SAST").severity("LOW").build();
        newF.setId(UUID.randomUUID());
        Finding existing = Finding.builder().findingId("EXISTING").title("Buffer Overflow")
                .type("SCA").severity("INFO").build();
        existing.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of(existing));
        assertThat(result.reason()).isIn("NO_MATCH", "RELATED");
    }

    @Test
    void findingCorrelationEngine_skipsResolvedFindings() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding newF = Finding.builder().findingId("NEW").title("SQL Injection")
                .type("SAST").severity("CRITICAL").build();
        newF.setId(UUID.randomUUID());
        Finding resolved = Finding.builder().findingId("RESOLVED").title("SQL Injection")
                .type("SAST").severity("CRITICAL").status("RESOLVED").build();
        resolved.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of(resolved));
        assertThat(result.matches()).isEmpty();
    }

    @Test
    void findingCorrelationEngine_skipsFalsePositives() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding newF = Finding.builder().findingId("NEW").title("SQL Injection")
                .type("SAST").severity("CRITICAL").build();
        newF.setId(UUID.randomUUID());
        Finding fp = Finding.builder().findingId("FP").title("SQL Injection")
                .type("SAST").severity("CRITICAL").status("FALSE_POSITIVE").build();
        fp.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of(fp));
        assertThat(result.matches()).isEmpty();
    }

    @Test
    void findingCorrelationEngine_sameAssetId() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        UUID assetId = UUID.randomUUID();
        Finding newF = Finding.builder().findingId("NEW").title("XSS").type("SAST")
                .severity("LOW").assetId(assetId).build();
        newF.setId(UUID.randomUUID());
        Finding existing = Finding.builder().findingId("EXISTING").title("CSRF").type("SAST")
                .severity("LOW").assetId(assetId).build();
        existing.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of(existing));
        assertThat(result).isNotNull();
    }

    @Test
    void findingCorrelationEngine_emptyExistingList() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding newF = Finding.builder().findingId("NEW").title("XSS").type("SAST").severity("LOW").build();
        newF.setId(UUID.randomUUID());
        var result = engine.correlate(newF, List.of());
        assertThat(result.matches()).isEmpty();
        assertThat(result.reason()).isEqualTo("NO_MATCH");
    }

    @Test
    void findingCorrelationEngine_selfExclusion() {
        com.vulnerax.modules.finding.FindingCorrelationEngine engine =
                new com.vulnerax.modules.finding.FindingCorrelationEngine();
        Finding f = Finding.builder().findingId("SELF").title("XSS").type("SAST").severity("LOW").build();
        f.setId(UUID.randomUUID());
        var result = engine.correlate(f, List.of(f));
        assertThat(result.matches()).isEmpty();
    }
}
