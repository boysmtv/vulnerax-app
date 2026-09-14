package com.vulnerax.modules.graph;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityGraphServiceTest {

    @Mock AssetRepository assetRepo;
    @Mock FindingRepository findingRepo;
    @InjectMocks SecurityGraphService service;

    private Asset buildAsset(UUID id, String name, String type, String criticality, Boolean exposed) {
        Asset a = new Asset();
        a.setId(id);
        a.setName(name);
        a.setType(type);
        a.setCriticality(criticality);
        a.setInternetExposed(exposed);
        a.setProjectId(UUID.randomUUID());
        a.setOrganizationId(UUID.randomUUID());
        return a;
    }

    private Finding buildFinding(UUID id, String title, String type, String severity, UUID assetId,
                                 String cwe, Double riskScore, Boolean internetExposed) {
        Finding f = Finding.builder()
                .title(title).type(type).severity(severity).confidence("HIGH")
                .assetId(assetId).cwe(cwe).riskScore(riskScore).internetExposed(internetExposed)
                .build();
        f.setId(id);
        f.setFindingId("FND-" + id.toString().substring(0, 8));
        return f;
    }

    @Test
    void graphForProject_withData_returnsNodesAndEdges() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Asset asset = buildAsset(assetId, "Web App", "WEBAPP", "HIGH", true);
        Finding finding = buildFinding(UUID.randomUUID(), "SQL Injection", "INJECTION", "CRITICAL",
                assetId, "CWE-89", 85.0, true);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(finding)));

        Map<String, Object> result = service.graphForProject(projectId);

        assertNotNull(result);
        assertNotNull(result.get("nodes"));
        assertNotNull(result.get("edges"));
        assertNotNull(result.get("stats"));

        List<Map<String, Object>> nodes = (List<Map<String, Object>>) result.get("nodes");
        assertTrue(nodes.size() >= 2); // 1 asset + 1 finding

        Map<String, Object> stats = (Map<String, Object>) result.get("stats");
        assertEquals(1, stats.get("assets"));
        assertEquals(1, stats.get("findings"));
    }

    @Test
    void graphForProject_nullProjectId_usesFindAll() {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));

        Map<String, Object> result = service.graphForProject(null);

        assertNotNull(result);
        verify(assetRepo).findAll();
        verify(findingRepo).findAll(any(PageRequest.class));
    }

    @Test
    void graphForProject_emptyData_returnsEmptyNodesAndEdges() {
        UUID projectId = UUID.randomUUID();
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of()));

        Map<String, Object> result = service.graphForProject(projectId);

        List<Map<String, Object>> nodes = (List<Map<String, Object>>) result.get("nodes");
        assertTrue(nodes.isEmpty());
        Map<String, Object> stats = (Map<String, Object>) result.get("stats");
        assertEquals(0, stats.get("assets"));
        assertEquals(0, stats.get("findings"));
    }

    @Test
    void graphForProject_findingWithAssetId_createsEdge() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Asset asset = buildAsset(assetId, "API Gateway", "API", "MEDIUM", false);
        Finding finding = buildFinding(UUID.randomUUID(), "XSS", "XSS", "MEDIUM",
                assetId, "CWE-79", 40.0, false);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(finding)));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> edges = (List<Map<String, Object>>) result.get("edges");

        boolean hasVulnEdge = edges.stream().anyMatch(e -> "HAS_VULN".equals(e.get("label")));
        assertTrue(hasVulnEdge, "Should have HAS_VULN edge from asset to finding");
    }

    @Test
    void graphForProject_cweChain_createsChainsToEdge() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID f1Id = UUID.randomUUID();
        UUID f2Id = UUID.randomUUID();

        Asset asset = buildAsset(assetId, "Server", "SERVER", "CRITICAL", true);
        Finding f1 = buildFinding(f1Id, "XSS", "XSS", "HIGH", assetId, "CWE-79", 70.0, true);
        Finding f2 = buildFinding(f2Id, "Injection", "INJECTION", "CRITICAL", assetId, "CWE-89", 90.0, true);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f1, f2)));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> edges = (List<Map<String, Object>>) result.get("edges");

        boolean hasChain = edges.stream().anyMatch(e -> "CHAINS_TO".equals(e.get("label")));
        assertTrue(hasChain, "CWE-79 -> CWE-89 should create CHAINS_TO edge");
    }

    @Test
    void graphForProject_findingWithNullAssetId_noEdge() {
        UUID projectId = UUID.randomUUID();
        Finding finding = buildFinding(UUID.randomUUID(), "Weak Config", "IAC", "LOW",
                null, "CWE-16", 15.0, false);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(finding)));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> edges = (List<Map<String, Object>>) result.get("edges");

        assertTrue(edges.isEmpty());
    }

    @Test
    void graphForProject_findingWithNullCriticality_usesDefault() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Asset asset = buildAsset(assetId, "DB", "DB", null, null);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of()));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> nodes = (List<Map<String, Object>>) result.get("nodes");

        assertEquals("MEDIUM", nodes.get(0).get("criticality"));
        assertEquals(false, nodes.get(0).get("exposed"));
    }

    @Test
    void graphForProject_findingWithNullRiskScore_usesDefault() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding f = buildFinding(UUID.randomUUID(), "Bug", "SAST", "MEDIUM",
                assetId, "CWE-0", null, false);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f)));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> nodes = (List<Map<String, Object>>) result.get("nodes");

        Map<String, Object> findingNode = nodes.stream()
                .filter(n -> "FINDING".equals(n.get("type")))
                .findFirst().orElse(null);
        assertNotNull(findingNode);
        assertEquals("LOW", findingNode.get("risk"));
    }

    @Test
    void attackPaths_withCriticalFinding_returnsPaths() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding critical = buildFinding(UUID.randomUUID(), "RCE", "RCE", "CRITICAL",
                assetId, "CWE-78", 95.0, true);
        critical.setAssetName("Production Server");

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(critical)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        Map<String, Object> path = paths.get(0);
        assertEquals("Production Server (Internet)", path.get("entryPoint"));
        assertEquals("Full System Compromise + Data Exfiltration", path.get("impact"));
    }

    @Test
    void attackPaths_withHighFinding_returnsHighImpact() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding high = buildFinding(UUID.randomUUID(), "BOLA", "AUTHORIZATION", "CRITICAL",
                assetId, "CWE-639", 65.0, false);
        high.setAssetName("Payment API");

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(high)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        Map<String, Object> path = paths.get(0);
        assertEquals("Privilege Escalation + Data Exposure", path.get("impact"));
    }

    @Test
    void attackPaths_withMediumFinding_returnsLimitedAccess() {
        UUID projectId = UUID.randomUUID();
        Finding medium = buildFinding(UUID.randomUUID(), "Info Leak", "INFO_DISCLOSURE", "CRITICAL",
                UUID.randomUUID(), "CWE-200", 45.0, false);
        medium.setAssetName("Internal API");

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(medium)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        assertEquals("Limited Access + Potential Lateral Movement", paths.get(0).get("impact"));
    }

    @Test
    void attackPaths_withLowFinding_returnsLowRisk() {
        UUID projectId = UUID.randomUUID();
        Finding low = buildFinding(UUID.randomUUID(), "Verbose Error", "INFO_DISCLOSURE", "CRITICAL",
                UUID.randomUUID(), "CWE-209", 10.0, false);

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(low)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        assertEquals("Low Risk - Hardening Recommended", paths.get(0).get("impact"));
    }

    @Test
    void attackPaths_nullProjectId_usesFindAll() {
        when(findingRepo.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));

        List<Map<String, Object>> paths = service.attackPaths(null);

        assertNotNull(paths);
        assertTrue(paths.isEmpty());
        verify(findingRepo).findAll(any(PageRequest.class));
    }

    @Test
    void attackPaths_secretFinding_addsCredentialExposure() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding secret = buildFinding(UUID.randomUUID(), "Hardcoded Key", "SECRET", "CRITICAL",
                assetId, null, 80.0, true);
        secret.setAssetName("Backend Service");

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(secret)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        List<String> chain = (List<String>) paths.get(0).get("chain");
        assertTrue(chain.contains("Credential Exposure"));
    }

    @Test
    void attackPaths_sastFinding_addsCodeExploitation() {
        UUID projectId = UUID.randomUUID();
        Finding sast = buildFinding(UUID.randomUUID(), "Buffer Overflow", "SAST", "CRITICAL",
                UUID.randomUUID(), "CWE-120", 60.0, false);

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(sast)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        List<String> chain = (List<String>) paths.get(0).get("chain");
        assertTrue(chain.contains("Code Exploitation"));
    }

    @Test
    void attackPaths_cweLinkedFinding_addsChainLink() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding xss = buildFinding(UUID.randomUUID(), "Reflected XSS", "XSS", "CRITICAL",
                assetId, "CWE-79", 50.0, true);
        xss.setAssetName("Web App");
        Finding sqli = buildFinding(UUID.randomUUID(), "SQL Injection", "INJECTION", "MEDIUM",
                assetId, "CWE-89", 30.0, false);

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(xss, sqli)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        List<String> chain = (List<String>) paths.get(0).get("chain");
        assertTrue(chain.stream().anyMatch(c -> c.startsWith("-> ")));
    }

    @Test
    void attackPaths_nullAssetName_usesDefault() {
        UUID projectId = UUID.randomUUID();
        Finding f = buildFinding(UUID.randomUUID(), "Bug", "SAST", "CRITICAL",
                UUID.randomUUID(), "CWE-0", 10.0, false);
        f.setAssetName(null);

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        assertEquals("unknown", paths.get(0).get("asset"));
    }

    @Test
    void attackPaths_nullRecommendation_usesDefault() {
        UUID projectId = UUID.randomUUID();
        Finding f = buildFinding(UUID.randomUUID(), "Bug", "SAST", "CRITICAL",
                UUID.randomUUID(), "CWE-0", 10.0, false);
        f.setRecommendation(null);

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertFalse(paths.isEmpty());
        assertEquals("Apply patch and validate access control", paths.get(0).get("mitigation"));
    }

    @Test
    void attackPaths_limitsTo10StartingPoints() {
        UUID projectId = UUID.randomUUID();
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            findings.add(buildFinding(UUID.randomUUID(), "Critical " + i, "RCE", "CRITICAL",
                    UUID.randomUUID(), "CWE-78", 90.0 + i, true));
        }

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(findings));

        List<Map<String, Object>> paths = service.attackPaths(projectId);

        assertTrue(paths.size() <= 10);
    }

    @Test
    void graphForProject_multipleFindingsOnSameAsset_cweChain() {
        UUID projectId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Asset asset = buildAsset(assetId, "App", "WEBAPP", "HIGH", true);

        Finding f1 = buildFinding(UUID.randomUUID(), "XSS", "XSS", "MEDIUM", assetId, "CWE-79", 50.0, false);
        Finding f2 = buildFinding(UUID.randomUUID(), "SQLi", "INJECTION", "CRITICAL", assetId, "CWE-89", 90.0, false);
        Finding f3 = buildFinding(UUID.randomUUID(), "Info Leak", "INFO_DISCLOSURE", "HIGH", assetId, "CWE-200", 60.0, false);

        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f1, f2, f3)));

        Map<String, Object> result = service.graphForProject(projectId);
        List<Map<String, Object>> edges = (List<Map<String, Object>>) result.get("edges");

        long chainCount = edges.stream().filter(e -> "CHAINS_TO".equals(e.get("label"))).count();
        assertTrue(chainCount >= 1, "Should have at least 1 CHAINS_TO edge");
    }

    @Test
    void attackPaths_duplicateFindingId_notVisitedTwice() {
        UUID projectId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        Finding f = buildFinding(findingId, "RCE", "RCE", "CRITICAL",
                UUID.randomUUID(), "CWE-78", 95.0, true);
        f.setAssetName("Server");

        when(findingRepo.findByProjectId(eq(projectId), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(f)));

        List<Map<String, Object>> paths = service.attackPaths(projectId);
        assertEquals(1, paths.size());
    }
}
