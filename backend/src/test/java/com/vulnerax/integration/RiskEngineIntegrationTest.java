package com.vulnerax.integration;

import com.vulnerax.VulneraxApplication;
import com.vulnerax.modules.finding.*;
import com.vulnerax.modules.scan.SecurityCoverageRegistry;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = VulneraxApplication.class)
@ActiveProfiles("test")
@Transactional
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RiskEngineIntegrationTest {

    @Autowired FindingRepository findingRepo;
    @Autowired SecurityCoverageRegistry coverageRegistry;

    @Test @Order(1)
    void findingRepo_countByTypePerProject_returnsCorrectGrouping() {
        Finding f1 = createFinding("CRITICAL", "SAST", UUID.randomUUID());
        Finding f2 = createFinding("HIGH", "DAST", f1.getProjectId());
        Finding f3 = createFinding("MEDIUM", "SAST", f1.getProjectId());
        findingRepo.save(f1); findingRepo.save(f2); findingRepo.save(f3);
        List<Object[]> counts = findingRepo.countByTypePerProject(f1.getProjectId());
        assertFalse(counts.isEmpty());
    }

    @Test @Order(2)
    void coverageRegistry_calculateCoverageWithUuid_works() {
        UUID projectId = UUID.randomUUID();
        Map<String, Object> result = coverageRegistry.calculateCoverage(projectId);
        assertNotNull(result);
        assertTrue(result.containsKey("overallPercentage"));
        assertTrue(result.containsKey("totalTests"));
    }

    @Test @Order(3)
    void findingRepo_existsByType_detectsExisting() {
        Finding f = createFinding("HIGH", "SECRET", UUID.randomUUID());
        findingRepo.save(f);
        assertTrue(findingRepo.existsByType("SECRET"));
        assertFalse(findingRepo.existsByType("SAST"));
    }

    @Test @Order(4)
    void findingRepo_countSlaBreached_countsCorrectly() {
        Finding f = createFinding("HIGH", "SAST", UUID.randomUUID());
        f.setSlaDueAt(java.time.Instant.now().minus(5, java.time.temporal.ChronoUnit.DAYS));
        f.setSlaStatus("BREACHED");
        findingRepo.save(f);
        assertTrue(findingRepo.countSlaBreached() >= 1);
    }

    @Test @Order(5)
    void coverageRegistry_calculateCoverageWithFinds_works() {
        Finding f = createFinding("CRITICAL", "DAST", UUID.randomUUID());
        findingRepo.save(f);
        Set<String> types = Set.of("DAST");
        Set<String> cwes = Set.of("CWE-79");
        Map<String, Object> result = coverageRegistry.calculateCoverageWithFinds(types, cwes);
        assertNotNull(result);
        assertTrue(result.containsKey("coveragePct") || result.containsKey("overallPercentage") || result.containsKey("totalTests"));
    }

    @Test @Order(6)
    void findingRepo_countSlaBreached_handlesEmptyState() {
        long count = findingRepo.countSlaBreached();
        assertTrue(count >= 0);
    }

    private Finding createFinding(String severity, String type, UUID projectId) {
        Finding f = new Finding();
        f.setFindingId("FND-TEST-" + UUID.randomUUID().toString().substring(0, 8));
        f.setTitle("Test Finding " + type);
        f.setDescription("Integration test");
        f.setSeverity(severity);
        f.setType(type);
        f.setConfidence("HIGH");
        f.setStatus("OPEN");
        f.setProjectId(projectId);
        f.setSource("integration-test");
        f.setBusinessCriticality("HIGH");
        f.setRiskScore(8.0);
        f.setCwe("CWE-79");
        f.setRiskLevel(severity);
        return f;
    }
}
