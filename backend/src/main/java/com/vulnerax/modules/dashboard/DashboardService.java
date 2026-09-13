package com.vulnerax.modules.dashboard;

import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.scan.ScanRepository;
import com.vulnerax.modules.scan.SecurityCoverageRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;

@Service
@RequiredArgsConstructor
public class DashboardService {
    private final FindingRepository findingRepo;
    private final AssetRepository assetRepo;
    private final ScanRepository scanRepo;
    private final SecurityCoverageRegistry coverageRegistry;

    public Map<String, Object> securityPosture(UUID projectId, UUID orgId) {
        UUID tenantOrgId = orgId != null ? orgId : TenantContext.getOrganizationId();

        // Project-scoped or global counts
        long totalAssets = projectId != null ? assetRepo.countByProjectId(projectId) : assetRepo.count();
        long totalFindings = projectId != null ? findingRepo.countByProjectId(projectId) : findingRepo.count();
        long critical = projectId != null ? findingRepo.countByProjectIdAndSeverity(projectId, "CRITICAL") : findingRepo.countBySeverity("CRITICAL");
        long high = projectId != null ? findingRepo.countByProjectIdAndSeverity(projectId, "HIGH") : findingRepo.countBySeverity("HIGH");
        long medium = projectId != null ? findingRepo.countByProjectIdAndSeverity(projectId, "MEDIUM") : findingRepo.countBySeverity("MEDIUM");
        long low = projectId != null ? findingRepo.countByProjectIdAndSeverity(projectId, "LOW") : findingRepo.countBySeverity("LOW");
        long info = projectId != null ? findingRepo.countByProjectIdAndSeverity(projectId, "INFO") : findingRepo.countBySeverity("INFO");

        long exposed = assetRepo.countByInternetExposedTrue();
        long kev = findingRepo.countByKev(true);

        // Security Score: 100 - weighted penalties
        double avgRisk = findingRepo.avgRiskScore() != null ? findingRepo.avgRiskScore() : 0;
        int score = (int) Math.max(0, Math.min(100, 100 - avgRisk * 0.7 - critical * 2 - high));

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("securityScore", score);
        posture.put("critical", critical);
        posture.put("high", high);
        posture.put("medium", medium);
        posture.put("low", low);
        posture.put("info", info);
        posture.put("totalFindings", totalFindings);
        posture.put("totalAssets", totalAssets);
        posture.put("internetExposed", exposed);
        posture.put("kev", kev);

        posture.put("bySeverity", Map.of("CRITICAL", critical, "HIGH", high, "MEDIUM", medium, "LOW", low, "INFO", info));

        // Real trend: last 7 days using COUNT queries (not loading all into memory)
        List<Map<String, Object>> trend = new ArrayList<>();
        LocalDate today = LocalDate.now();
        for (int i = 6; i >= 0; i--) {
            LocalDate d = today.minusDays(i);
            long c = findingRepo.countBySeverityAndDate("CRITICAL", d);
            long h = findingRepo.countBySeverityAndDate("HIGH", d);
            trend.add(Map.of("date", d.toString(), "critical", c, "high", h));
        }
        posture.put("trend", trend);

        posture.put("topRiskAssets", assetRepo.findTopRiskAssets(5));

        // Real coverage: use SecurityCoverageRegistry.calculateCoverage() for percentage
        Map<String, Object> coverage = new LinkedHashMap<>();
        Set<String> testedTypes = new HashSet<>();
        for (String type : List.of("SAST", "SCA", "SECRET", "DAST", "API", "MOBILE", "CONTAINER", "IAC")) {
            boolean hasScan = scanRepo.existsByScannerType(type);
            boolean hasFindings = findingRepo.existsByType(type);
            if (hasScan || hasFindings) testedTypes.add(type);
        }
        Map<String, Object> coverageTests = coverageRegistry.calculateCoverage(projectId != null ? projectId : null);
        coverage.put("testedTypes", testedTypes.size());
        coverage.put("totalTypes", 8);
        coverage.put("percentage", coverageTests.getOrDefault("overallPercentage", 0));
        coverage.put("details", coverageTests.getOrDefault("tested", List.of()));
        posture.put("coverage", coverage);

        // Real asset type breakdown from DB
        List<Object[]> assetTypes = assetRepo.countByType();
        Map<String, Long> assetTypeMap = new LinkedHashMap<>();
        for (Object[] row : assetTypes) assetTypeMap.put((String) row[0], (Long) row[1]);
        posture.put("assetTypes", assetTypeMap);

        return posture;
    }

    public Map<String, Object> applicationDashboard(UUID projectId) {
        Map<String, Object> m = securityPosture(projectId, null);
        m.put("projectId", projectId);
        m.put("repositories", assetRepo.countByType("REPOSITORY"));
        m.put("apis", assetRepo.countByType("API"));
        m.put("mobileApps", assetRepo.countByType("MOBILE"));
        m.put("cloudResources", assetRepo.countByType("CLOUD"));
        m.put("containers", assetRepo.countByType("CONTAINER"));
        return m;
    }
}
