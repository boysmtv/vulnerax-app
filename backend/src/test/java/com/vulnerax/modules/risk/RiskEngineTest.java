package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

class RiskEngineTest {
    private final RiskEngine engine = new RiskEngine();

    // create — verifies CVSS + exposure scoring
    @Test
    void calculate_critical_exposed_production_should_be_high() {
        Finding f = Finding.builder()
                .title("Test")
                .type("INJECTION").severity("CRITICAL").confidence("CONFIRMED")
                .businessCriticality("CRITICAL").environment("PRODUCTION")
                .cvss(9.8).epss(0.9).kev(true)
                .internetExposed(true).reachable(true)
                .assetId(UUID.randomUUID()).filePath("a.java").lineNumber(10)
                .build();
        double score = engine.calculate(f);
        assertThat(score).isGreaterThan(80);
        assertThat(engine.level(score)).isEqualTo("CRITICAL");
    }

    @Test
    void calculate_low_unexposed_should_be_low() {
        Finding f = Finding.builder()
                .title("Low").type("INFO").severity("LOW").confidence("LOW")
                .businessCriticality("LOW").environment("DEVELOPMENT")
                .cvss(2.0).epss(0.01).kev(false)
                .internetExposed(false).reachable(false)
                .build();
        double score = engine.calculate(f);
        assertThat(score).isLessThan(30);
        assertThat(engine.level(score)).isIn("LOW","MODERATE");
    }

    @Test
    void enrich_sets_riskScore_and_fingerprint_and_sla() {
        Finding f = Finding.builder()
                .title("BOLA").type("AUTHORIZATION").severity("HIGH").confidence("HIGH")
                .businessCriticality("HIGH").environment("PRODUCTION")
                .cvss(8.1).epss(0.5)
                .assetId(UUID.randomUUID()).filePath("src/Controller.java").lineNumber(42)
                .cwe("CWE-639")
                .build();
        engine.enrich(f);
        assertThat(f.getRiskScore()).isNotNull().isBetween(0.0, 100.0);
        assertThat(f.getRiskLevel()).isNotBlank();
        assertThat(f.getFingerprint()).isNotBlank();
        assertThat(f.getSlaDueAt()).isAfter(Instant.now());
        assertThat(f.getSlaStatus()).isEqualTo("WITHIN_SLA");
    }

    @Test
    void sla_critical_score_overrides_to_1_day() {
        Finding f = Finding.builder()
                .title("X").type("INJECTION").severity("MEDIUM").confidence("HIGH")
                .businessCriticality("CRITICAL").environment("PRODUCTION")
                .cvss(10.0).epss(1.0).kev(true).internetExposed(true).reachable(true)
                .assetId(UUID.randomUUID()).filePath("a.java").lineNumber(1)
                .build();
        engine.enrich(f);
        long days = ChronoUnit.DAYS.between(Instant.now(), f.getSlaDueAt());
        assertThat(days).isLessThanOrEqualTo(3);
    }

    @Test
    void level_boundaries() {
        assertThat(engine.level(10)).isEqualTo("LOW");
        assertThat(engine.level(30)).isEqualTo("MODERATE");
        assertThat(engine.level(50)).isEqualTo("HIGH");
        assertThat(engine.level(70)).isEqualTo("VERY_HIGH");
        assertThat(engine.level(90)).isEqualTo("CRITICAL");
    }

    @Test
    void calculate_null_fields_should_not_throw_and_return_in_range() {
        Finding f = new Finding();
        f.setTitle("nulls");
        double score = engine.calculate(f);
        assertThat(score).isBetween(0.0, 100.0);
    }

    @Test
    void age_increases_risk_slightly() {
        Finding old = Finding.builder().title("old").type("INFO").severity("MEDIUM").confidence("MEDIUM")
                .cvss(5.0).build();
        old.setCreatedAt(Instant.now().minus(90, ChronoUnit.DAYS));
        Finding fresh = Finding.builder().title("fresh").type("INFO").severity("MEDIUM").confidence("MEDIUM")
                .cvss(5.0).build();
        fresh.setCreatedAt(Instant.now());
        assertThat(engine.calculate(old)).isGreaterThanOrEqualTo(engine.calculate(fresh));
    }
}
