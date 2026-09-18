package com.vulnerax.modules.coverage;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CoverageEngine {
    private final FindingRepository findingRepo;

    public CoverageReport calculate(UUID projectId) {
        List<Finding> allFindings = projectId != null ? findingRepo.findByProjectId(projectId) : findingRepo.findAll();

        long totalFindings = allFindings.size();
        long confirmedVulns = allFindings.stream()
                .filter(f -> "VULNERABILITY".equals(f.getFindingType()) && Boolean.TRUE.equals(f.getVulnerabilityConfirmed()))
                .count();
        long scanIssues = allFindings.stream()
                .filter(f -> "SCAN_ERROR".equals(f.getFindingType()))
                .count();
        long misconfigs = allFindings.stream()
                .filter(f -> "MISCONFIGURATION".equals(f.getFindingType()))
                .count();
        long exposures = allFindings.stream()
                .filter(f -> "EXPOSURE".equals(f.getFindingType()))
                .count();
        long informational = allFindings.stream()
                .filter(f -> "INFORMATIONAL".equals(f.getFindingType()))
                .count();

        // Coverage by scanner type
        Map<String, Long> bySource = allFindings.stream()
                .collect(Collectors.groupingBy(Finding::getSource, Collectors.counting()));

        // Coverage by endpoint
        Set<String> testedEndpoints = allFindings.stream()
                .map(Finding::getAssetName)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        double overallCoverage = totalFindings > 0 ? Math.min(100, (testedEndpoints.size() * 10.0)) : 0;

        return new CoverageReport(
                totalFindings,
                confirmedVulns,
                scanIssues,
                misconfigs,
                exposures,
                informational,
                overallCoverage,
                bySource,
                testedEndpoints
        );
    }

    public record CoverageReport(
            long totalFindings,
            long confirmedVulnerabilities,
            long scanIssues,
            long misconfigurations,
            long exposures,
            long informational,
            double overallCoverage,
            Map<String, Long> findingsBySource,
            Set<String> testedEndpoints
    ) {}
}
