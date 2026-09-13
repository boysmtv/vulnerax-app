package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class RiskEngineTest {

    private RiskEngine engine;

    @BeforeEach
    void setUp() {
        engine = new RiskEngine();
    }

    private Finding buildFinding(String severity, Double cvss, Boolean kev, Boolean exposed, String crit) {
        Finding f = Finding.builder()
                .cvss(cvss).epss(0.5).kev(kev)
                .businessCriticality(crit).internetExposed(exposed)
                .reachable(false).environment("PRODUCTION")
                .confidence("HIGH").severity(severity)
                .build();
        f.setCreatedAt(Instant.now());
        return f;
    }

    @Test
    void calculatesRiskScoreWithAllFactors() {
        Finding f = buildFinding("HIGH", 7.5, false, false, "HIGH");
        double score = engine.calculate(f);
        assertTrue(score > 0, "Score should be > 0");
        assertTrue(score <= 100, "Score should be <= 100");
    }

    @Test
    void returnsHigherScoreForCriticalSeverity() {
        Finding critical = buildFinding("CRITICAL", 9.8, false, true, "CRITICAL");
        Finding low = buildFinding("LOW", 2.0, false, false, "LOW");
        assertTrue(engine.calculate(critical) > engine.calculate(low));
    }

    @Test
    void increasesScoreForKevExploitation() {
        Finding withKev = buildFinding("HIGH", 7.0, true, false, "HIGH");
        Finding withoutKev = buildFinding("HIGH", 7.0, false, false, "HIGH");
        assertTrue(engine.calculate(withKev) > engine.calculate(withoutKev));
    }

    @Test
    void increasesScoreForInternetExposed() {
        Finding exposed = buildFinding("HIGH", 7.0, false, true, "HIGH");
        Finding notExposed = buildFinding("HIGH", 7.0, false, false, "HIGH");
        assertTrue(engine.calculate(exposed) > engine.calculate(notExposed));
    }

    @Test
    void returnsCorrectRiskLevels() {
        assertEquals("CRITICAL", engine.level(85));
        assertEquals("VERY_HIGH", engine.level(65));
        assertEquals("HIGH", engine.level(45));
        assertEquals("MODERATE", engine.level(25));
        assertEquals("LOW", engine.level(10));
    }

    @Test
    void enrichesFinding() {
        Finding f = buildFinding("HIGH", 8.0, false, false, "HIGH");
        engine.enrich(f);
        assertTrue(f.getRiskScore() > 0);
        assertNotNull(f.getRiskLevel());
        assertNotNull(f.getSlaDueAt());
        assertEquals("WITHIN_SLA", f.getSlaStatus());
        assertNotNull(f.getFingerprint());
    }

    @Test
    void generatesFingerprintForDedup() {
        Finding f = Finding.builder()
                .assetId(UUID.randomUUID()).type("SAST").cwe("CWE-89")
                .filePath("test.java").lineNumber(10)
                .severity("HIGH").confidence("HIGH").build();
        f.setCreatedAt(Instant.now());
        engine.enrich(f);
        assertNotNull(f.getFingerprint());
        assertTrue(f.getFingerprint().matches("[a-f0-9]+"));
    }
}
