package com.vulnerax.modules.dashboard;

import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.scan.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

@Service
@RequiredArgsConstructor
public class DashboardService {
    private final FindingRepository findingRepo;
    private final AssetRepository assetRepo;
    private final ScanRepository scanRepo;

    public Map<String, Object> securityPosture(UUID projectId, UUID orgId) {
        UUID tenantOrgId = orgId != null ? orgId : TenantContext.getOrganizationId();

        long totalAssets = assetRepo.count();
        long totalFindings = findingRepo.count();
        long critical = findingRepo.countBySeverity("CRITICAL");
        long high = findingRepo.countBySeverity("HIGH");
        long medium = findingRepo.countBySeverity("MEDIUM");
        long low = findingRepo.countBySeverity("LOW");
        long info = findingRepo.countBySeverity("INFO");

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
        posture.put("coverage", Map.of(
                "SAST", scanRepo.existsByScannerType("SAST") ? "✓" : "○",
                "SCA", scanRepo.existsByScannerType("SCA") ? "✓" : "○",
                "SECRET", findingRepo.existsByType("SECRET") ? "✓" : "○",
                "DAST", scanRepo.existsByScannerType("DAST") ? "✓" : "○",
                "API", scanRepo.existsByScannerType("API") ? "✓" : "○",
                "MOBILE", scanRepo.existsByScannerType("MOBILE") ? "✓" : "○",
                "CONTAINER", scanRepo.existsByScannerType("CONTAINER") ? "✓" : "○",
                "IAC", scanRepo.existsByScannerType("IAC") ? "✓" : "○"
        ));
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
