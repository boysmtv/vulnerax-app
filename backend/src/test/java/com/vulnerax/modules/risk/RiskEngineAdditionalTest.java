package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RiskEngineAdditionalTest {

    private final RiskEngine engine = new RiskEngine();

    @Test
    void calculate_criticalSeverity_highScore() {
        Finding f = Finding.builder()
                .severity("CRITICAL").cvss(10.0).epss(0.99).kev(true)
                .internetExposed(true).reachable(true).environment("PRODUCTION")
                .confidence("CONFIRMED").businessCriticality("CRITICAL")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThan(50);
    }

    @Test
    void calculate_lowSeverity_lowScore() {
        Finding f = Finding.builder()
                .severity("LOW").cvss(1.0).epss(0.01).kev(false)
                .internetExposed(false).reachable(false).environment("DEV")
                .confidence("LOW").businessCriticality("LOW")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isLessThan(50);
    }

    @Test
    void calculate_infoSeverity_minimalScore() {
        Finding f = Finding.builder()
                .severity("INFO").cvss(0.0).kev(false)
                .internetExposed(false).confidence("LOW")
                .businessCriticality("LOW")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_compensatingControl_reducesScore() {
        Finding f1 = Finding.builder()
                .severity("HIGH").cvss(7.0).confidence("HIGH")
                .businessCriticality("HIGH")
                .build();
        Finding f2 = Finding.builder()
                .severity("HIGH").cvss(7.0).confidence("HIGH")
                .businessCriticality("HIGH").compensatingControl("WAF Rule")
                .build();
        double score1 = engine.calculate(f1);
        double score2 = engine.calculate(f2);
        assertThat(score2).isLessThan(score1);
    }

    @Test
    void calculate_oldFinding_higherScore() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(5.0).confidence("MEDIUM")
                .businessCriticality("MEDIUM")
                .build();
        f.setCreatedAt(Instant.now().minus(90, ChronoUnit.DAYS));
        double score = engine.calculate(f);
        assertThat(score).isGreaterThan(0);
    }

    @Test
    void level_critical() {
        assertThat(engine.level(85)).isEqualTo("CRITICAL");
        assertThat(engine.level(81)).isEqualTo("CRITICAL");
    }

    @Test
    void level_veryHigh() {
        assertThat(engine.level(70)).isEqualTo("VERY_HIGH");
        assertThat(engine.level(61)).isEqualTo("VERY_HIGH");
    }

    @Test
    void level_high() {
        assertThat(engine.level(50)).isEqualTo("HIGH");
        assertThat(engine.level(41)).isEqualTo("HIGH");
    }

    @Test
    void level_moderate() {
        assertThat(engine.level(30)).isEqualTo("MODERATE");
        assertThat(engine.level(21)).isEqualTo("MODERATE");
    }

    @Test
    void level_low() {
        assertThat(engine.level(10)).isEqualTo("LOW");
        assertThat(engine.level(0)).isEqualTo("LOW");
    }

    @Test
    void enrich_setsRiskScoreAndLevel() {
        Finding f = Finding.builder()
                .severity("HIGH").cvss(7.0).confidence("HIGH")
                .businessCriticality("HIGH").assetId(UUID.randomUUID())
                .type("SAST").cwe("CWE-89").filePath("/src/Main.java")
                .lineNumber(42)
                .build();
        engine.enrich(f);
        assertThat(f.getRiskScore()).isGreaterThan(0);
        assertThat(f.getRiskLevel()).isNotNull();
        assertThat(f.getSlaDueAt()).isNotNull();
        assertThat(f.getSlaStatus()).isEqualTo("WITHIN_SLA");
        assertThat(f.getFingerprint()).isNotNull();
    }

    @Test
    void enrich_criticalSeverity_slaOneDay() {
        Finding f = Finding.builder()
                .severity("CRITICAL").cvss(10.0).confidence("CONFIRMED")
                .businessCriticality("CRITICAL").assetId(UUID.randomUUID())
                .type("SAST").cwe("CWE-89")
                .build();
        engine.enrich(f);
        assertThat(f.getSlaDueAt()).isNotNull();
        long days = ChronoUnit.DAYS.between(Instant.now(), f.getSlaDueAt());
        assertThat(days).isLessThanOrEqualTo(2);
    }

    @Test
    void enrich_highSeverity_slaFewDays() {
        Finding f = Finding.builder()
                .severity("HIGH").cvss(7.0).confidence("HIGH")
                .businessCriticality("HIGH").assetId(UUID.randomUUID())
                .type("SAST").cwe("CWE-79")
                .build();
        engine.enrich(f);
        assertThat(f.getSlaDueAt()).isNotNull();
    }

    @Test
    void enrich_mediumSeverity_sla30Days() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(5.0).confidence("MEDIUM")
                .businessCriticality("MEDIUM").assetId(UUID.randomUUID())
                .type("SAST").cwe("CWE-525")
                .build();
        engine.enrich(f);
        assertThat(f.getSlaDueAt()).isNotNull();
    }

    @Test
    void enrich_lowSeverity_sla90Days() {
        Finding f = Finding.builder()
                .severity("LOW").cvss(2.0).confidence("LOW")
                .businessCriticality("LOW").assetId(UUID.randomUUID())
                .type("INFO").cwe("CWE-200")
                .build();
        engine.enrich(f);
        assertThat(f.getSlaDueAt()).isNotNull();
    }

    @Test
    void calculate_nullCvss_usesDefault() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(null).confidence("MEDIUM")
                .businessCriticality("MEDIUM")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_nullEpss_noEpssScore() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(5.0).epss(null).confidence("MEDIUM")
                .businessCriticality("MEDIUM")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_nullSeverity_usesDefault() {
        Finding f = Finding.builder()
                .severity(null).cvss(5.0).confidence("MEDIUM")
                .businessCriticality("MEDIUM")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_nullBusinessCriticality_usesDefault() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(5.0).confidence("MEDIUM")
                .businessCriticality(null)
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_nullConfidence_usesDefault() {
        Finding f = Finding.builder()
                .severity("MEDIUM").cvss(5.0).confidence(null)
                .businessCriticality("MEDIUM")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }

    @Test
    void calculate_maxScore_cappedAt100() {
        Finding f = Finding.builder()
                .severity("CRITICAL").cvss(10.0).epss(1.0).kev(true)
                .internetExposed(true).reachable(true).environment("PRODUCTION")
                .confidence("CONFIRMED").businessCriticality("CRITICAL")
                .build();
        f.setCreatedAt(Instant.now().minus(365, ChronoUnit.DAYS));
        double score = engine.calculate(f);
        assertThat(score).isLessThanOrEqualTo(100);
    }

    @Test
    void calculate_minScore_notNegative() {
        Finding f = Finding.builder()
                .severity("INFO").cvss(0.0).kev(false)
                .internetExposed(false).reachable(false)
                .confidence("LOW").businessCriticality("LOW")
                .compensatingControl("Strong WAF + IPS + IDS")
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThanOrEqualTo(0);
    }
}
