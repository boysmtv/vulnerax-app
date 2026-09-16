package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class EnrichmentService {

    public Map<String, Object> enrich(Finding finding) {
        Map<String, Object> enrichment = new LinkedHashMap<>();
        enrichment.put("findingId", finding.getId());

        // Risk calculation
        double scanCoverage = finding.getCoveragePercentage() != null ? finding.getCoveragePercentage() : 0;
        RiskEngine.RiskResult risk = RiskEngine.calculate(
                Boolean.TRUE.equals(finding.getVulnerabilityConfirmed()),
                finding.getSeverity(),
                finding.getCvss() != null ? finding.getCvss() : 0,
                Boolean.TRUE.equals(finding.getInternetExposed()),
                Boolean.TRUE.equals(finding.getKev()),
                finding.getBusinessCriticality() != null ? finding.getBusinessCriticality() : "MEDIUM",
                "INTERNAL",
                scanCoverage,
                finding.getFindingType()
        );

        enrichment.put("securityRisk", risk.securityRisk());
        enrichment.put("coverageRisk", risk.coverageRisk());
        enrichment.put("riskBreakdown", risk.breakdown());
        enrichment.put("riskExplanation", risk.explanation());

        // Compliance mapping
        String cwe = finding.getCwe();
        if (cwe != null) {
            enrichment.put("owasp", com.vulnerax.modules.compliance.OwaspMapper.getOwasp(cwe));
            enrichment.put("asvs", com.vulnerax.modules.compliance.OwaspMapper.getAsvs(cwe));
            enrichment.put("wstg", com.vulnerax.modules.compliance.OwaspMapper.getWstg(cwe));
        }

        return enrichment;
    }
}
