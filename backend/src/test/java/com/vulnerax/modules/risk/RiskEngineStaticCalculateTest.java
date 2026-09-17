package com.vulnerax.modules.risk;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RiskEngineStaticCalculateTest {

    @Test
    void vulnerabilityConfirmedWithHighCvss_highSecurityRisk() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "CRITICAL", 9.8, true, true, "CRITICAL", "RESTRICTED", 50.0, "SAST");

        assertTrue(result.securityRisk() > 0, "Security risk should be > 0");
        assertTrue(result.securityRisk() <= 100, "Security risk should be <= 100");
        assertNotNull(result.securityRiskLevel());
        assertNotNull(result.coverageRiskLevel());
    }

    @Test
    void vulnerabilityNotConfirmed_securityRiskZero() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                false, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 80.0, "DAST");

        assertEquals(0, result.securityRisk(), "Security risk should be 0 when not confirmed");
        assertTrue(result.coverageRisk() > 0, "Coverage risk should be > 0 when coverage < 100");
    }

    @Test
    void cvssScoreZero_securityRiskZero() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 0.0, false, false, "MEDIUM", "INTERNAL", 80.0, "SAST");

        assertEquals(0, result.securityRisk(), "Security risk should be 0 when cvss is 0");
    }

    @Test
    void kevExploitation_increasesExploitability() {
        RiskEngine.RiskResult withKev = RiskEngine.calculate(
                true, "HIGH", 7.0, false, true, "MEDIUM", "INTERNAL", 80.0, "SAST");
        RiskEngine.RiskResult withoutKev = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 80.0, "SAST");

        assertTrue(withKev.securityRisk() > withoutKev.securityRisk(),
                "KEV should increase security risk");
    }

    @Test
    void internetExposed_increasesExploitability() {
        RiskEngine.RiskResult exposed = RiskEngine.calculate(
                true, "HIGH", 7.0, true, false, "MEDIUM", "INTERNAL", 80.0, "SAST");
        RiskEngine.RiskResult notExposed = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 80.0, "SAST");

        assertTrue(exposed.securityRisk() > notExposed.securityRisk(),
                "Internet exposure should increase security risk");
    }

    @Test
    void businessCriticalityCritical_highestAssetCriticality() {
        RiskEngine.RiskResult critical = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "CRITICAL", "INTERNAL", 80.0, "SAST");
        RiskEngine.RiskResult low = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "LOW", "INTERNAL", 80.0, "SAST");

        assertTrue(critical.securityRisk() > low.securityRisk(),
                "CRITICAL business criticality should yield higher risk than LOW");
    }

    @Test
    void businessCriticalityNull_defaultsToMedium() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, null, "INTERNAL", 80.0, "SAST");

        // Should use default MEDIUM (6.0) for null businessCriticality
        assertTrue(result.securityRisk() > 0);
    }

    @Test
    void dataClassificationRestricted_highestSensitivity() {
        RiskEngine.RiskResult restricted = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "RESTRICTED", 80.0, "SAST");
        RiskEngine.RiskResult public_ = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "PUBLIC", 80.0, "SAST");

        assertTrue(restricted.securityRisk() > public_.securityRisk(),
                "RESTRICTED data should yield higher risk than PUBLIC");
    }

    @Test
    void dataClassificationNull_defaultsToInternal() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", null, 80.0, "SAST");

        // Should use default INTERNAL (4.0) for null dataClassification
        assertTrue(result.securityRisk() > 0);
    }

    @Test
    void scanCoverage100_noCoverageRisk() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 100.0, "SAST");

        assertEquals(0, result.coverageRisk(), "Coverage risk should be 0 when coverage is 100%");
    }

    @Test
    void scanCoverageLow_highCoverageRisk() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 0.0, "SAST");

        assertTrue(result.coverageRisk() > 50, "Low coverage should yield high coverage risk");
        assertEquals("HIGH", result.coverageRiskLevel());
    }

    @Test
    void coverageRiskMedium() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 60.0, "SAST");

        // coverageRisk = (100-60)*0.8 = 32, which is < 40 => LOW
        assertEquals("LOW", result.coverageRiskLevel());
    }

    @Test
    void coverageRiskMediumRange() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 40.0, "SAST");

        // coverageRisk = (100-40)*0.8 = 48, which is >= 40 && < 70 => MEDIUM
        assertEquals("MEDIUM", result.coverageRiskLevel());
    }

    @Test
    void criticalBusinessCriticality_coverageRiskMultiplier() {
        RiskEngine.RiskResult critical = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "CRITICAL", "INTERNAL", 50.0, "SAST");
        RiskEngine.RiskResult medium = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 50.0, "SAST");

        assertTrue(critical.coverageRisk() > medium.coverageRisk(),
                "CRITICAL business criticality should multiply coverage risk by 1.3");
    }

    @Test
    void highBusinessCriticality_coverageRiskMultiplier() {
        RiskEngine.RiskResult high = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "HIGH", "INTERNAL", 50.0, "SAST");
        RiskEngine.RiskResult medium = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 50.0, "SAST");

        assertTrue(high.coverageRisk() > medium.coverageRisk(),
                "HIGH business criticality should multiply coverage risk by 1.3");
    }

    @Test
    void coverageRiskCappedAt100() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "CRITICAL", "INTERNAL", 0.0, "SAST");

        assertTrue(result.coverageRisk() <= 100, "Coverage risk should be capped at 100");
    }

    @Test
    void securityRiskCappedAt100() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "CRITICAL", 10.0, true, true, "CRITICAL", "RESTRICTED", 0.0, "SAST");

        assertTrue(result.securityRisk() <= 100, "Security risk should be capped at 100");
    }

    @Test
    void breakdownContainsAllComponents() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, true, true, "CRITICAL", "RESTRICTED", 50.0, "SAST");

        assertTrue(result.breakdown().containsKey("technical_severity"));
        assertTrue(result.breakdown().containsKey("exploitability"));
        assertTrue(result.breakdown().containsKey("asset_criticality"));
        assertTrue(result.breakdown().containsKey("data_sensitivity"));
    }

    @Test
    void explanationContainsFinalRiskValues() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "INTERNAL", 80.0, "SAST");

        assertTrue(result.explanation().containsKey("final_security_risk"));
        assertTrue(result.explanation().containsKey("final_coverage_risk"));
        assertTrue(result.explanation().get("final_security_risk").contains("/100"));
        assertTrue(result.explanation().get("final_coverage_risk").contains("scan coverage: 80%"));
    }

    @Test
    void unknownBusinessCriticality_usesDefault() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "UNKNOWN", "INTERNAL", 80.0, "SAST");

        // UNKNOWN -> default 2.0
        assertEquals(2.0, result.breakdown().get("asset_criticality"));
    }

    @Test
    void unknownDataClassification_usesDefault() {
        RiskEngine.RiskResult result = RiskEngine.calculate(
                true, "HIGH", 7.0, false, false, "MEDIUM", "UNKNOWN", 80.0, "SAST");

        // UNKNOWN -> default 1.0
        assertEquals(1.0, result.breakdown().get("data_sensitivity"));
    }
}
