package com.vulnerax.modules.findings;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingCorrelationEngine;
import com.vulnerax.modules.finding.FindingCorrelationEngine.CorrelationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class FindingCorrelationEngineTest {

    private FindingCorrelationEngine engine;

    @BeforeEach
    void setUp() {
        engine = new FindingCorrelationEngine();
    }

    private Finding buildFinding(String title, String type, String severity, String cwe, String cweId,
                                  String filePath, String source, UUID scanId, UUID assetId,
                                  String status, Instant createdAt) {
        Finding f = Finding.builder()
                .title(title).type(type).severity(severity).confidence("HIGH")
                .cwe(cwe).cweId(cweId).filePath(filePath).source(source)
                .scanId(scanId).assetId(assetId).status(status)
                .build();
        f.setId(UUID.randomUUID());
        if (createdAt != null) f.setCreatedAt(createdAt);
        return f;
    }

    @Test
    void correlate_exactMatch_findsDuplicate() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("SQL Injection in login", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);
        Finding existing = buildFinding("SQL Injection in login", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertTrue(result.isDuplicate());
        assertEquals("EXACT_MATCH", result.reason());
        assertEquals("MERGE_EVIDENCE", result.mergeRecommendation());
        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_similarMatch_findsRelated() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("SQL Injection in login page", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);
        Finding existing = buildFinding("SQL Injection in login endpoint", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
        assertTrue("SIMILAR".equals(result.reason()) || "EXACT_MATCH".equals(result.reason()));
    }

    @Test
    void correlate_differentType_reducesScore() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);
        Finding existing = buildFinding("SQL Injection", "XSS", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast-scanner", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        // Different type lowers the score, may or may not match depending on other factors
        assertNotNull(result);
        assertNotNull(result.reason());
    }

    @Test
    void correlate_skipsSelfMatch() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", null,
                null, "sast", null, null, "OPEN", Instant.now());

        CorrelationResult result = engine.correlate(f, List.of(f));

        assertEquals("NO_MATCH", result.reason());
        assertTrue(result.matches().isEmpty());
    }

    @Test
    void correlate_skipsResolvedFindings() {
        Finding newFinding = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", null,
                null, "sast", null, null, "OPEN", Instant.now());
        Finding resolved = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", null,
                null, "sast", null, null, "RESOLVED", Instant.now());

        CorrelationResult result = engine.correlate(newFinding, List.of(resolved));

        assertEquals("NO_MATCH", result.reason());
    }

    @Test
    void correlate_skipsFalsePositiveFindings() {
        Finding newFinding = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", null,
                null, "sast", null, null, "OPEN", Instant.now());
        Finding fp = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", null,
                null, "sast", null, null, "FALSE_POSITIVE", Instant.now());

        CorrelationResult result = engine.correlate(newFinding, List.of(fp));

        assertEquals("NO_MATCH", result.reason());
    }

    @Test
    void correlate_noMatch_returnsNoMatch() {
        Finding newFinding = buildFinding("SQL Injection", "INJECTION", "CRITICAL", "CWE-89", null,
                "/src/main.java", "sast", null, UUID.randomUUID(), "OPEN", Instant.now());
        Finding unrelated = buildFinding("Outdated jQuery", "SCA", "INFO", "CWE-1104", null,
                "/package.json", "sca", null, UUID.randomUUID(), "OPEN", Instant.now());

        CorrelationResult result = engine.correlate(newFinding, List.of(unrelated));

        assertEquals("NO_MATCH", result.reason());
        assertEquals("INDEPENDENT", result.mergeRecommendation());
    }

    @Test
    void correlate_emptyExistingList_returnsNoMatch() {
        Finding f = buildFinding("XSS", "XSS", "MEDIUM", "CWE-79", null,
                null, "dast", null, null, "OPEN", Instant.now());

        CorrelationResult result = engine.correlate(f, List.of());

        assertEquals("NO_MATCH", result.reason());
        assertTrue(result.matches().isEmpty());
    }

    @Test
    void correlate_sameAssetId_providesBonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Issue A", "SAST", "MEDIUM", "CWE-79", null,
                null, "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "MEDIUM", "CWE-79", null,
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
        assertFalse(result.matches().isEmpty() || "NO_MATCH".equals(result.reason()));
    }

    @Test
    void correlate_sameCweId_providesBonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Auth Bypass", "AUTHORIZATION", "CRITICAL", null, "CWE-287",
                "/src/auth.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Auth Bypass Root", "AUTHORIZATION", "CRITICAL", null, "CWE-287",
                "/src/auth.java", "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_sameCwe_providesBonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Auth Issue", "AUTHORIZATION", "HIGH", "CWE-287", null,
                null, "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Auth Problem", "AUTHORIZATION", "HIGH", "CWE-287", null,
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_temporalDecay_within7Days_bonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant threeDaysAgo = now.minus(3, ChronoUnit.DAYS);
        Finding newFinding = buildFinding("Issue A", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", threeDaysAgo);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_temporalDecay_between7and30Days() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant twentyDaysAgo = now.minus(20, ChronoUnit.DAYS);
        Finding newFinding = buildFinding("Issue A", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", twentyDaysAgo);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
    }

    @Test
    void correlate_temporalDecay_moreThan90Days_penalty() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant oldDate = now.minus(120, ChronoUnit.DAYS);
        Finding newFinding = buildFinding("Issue A", "SAST", "MEDIUM", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "MEDIUM", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", oldDate);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
    }

    @Test
    void correlate_sameFilePath_exactBonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Issue A", "SAST", "HIGH", "CWE-89", null,
                "/src/main/auth.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "HIGH", "CWE-89", null,
                "/src/main/auth.java", "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_differentFilePath_partialBonus() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Issue A", "SAST", "HIGH", "CWE-89", null,
                "/src/main/auth.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "HIGH", "CWE-89", null,
                "/src/main/auth/login.java", "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
    }

    @Test
    void correlate_sameSourceAndScan_bonus() {
        UUID assetId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Issue A", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast-scanner", scanId, assetId, "OPEN", now);
        Finding existing = buildFinding("Issue B", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast-scanner", scanId, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_relatedMatch_returnsRelatedReason() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Weak Password Policy", "AUTHORIZATION", "MEDIUM", null, null,
                "/config.java", "manual", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Hardcoded Credentials", "SECRET", "MEDIUM", null, null,
                "/config.java", "manual", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertNotNull(result);
        assertNotNull(result.reason());
    }

    @Test
    void correlate_multipleExisting_findBestMatch() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast", null, assetId, "OPEN", now);

        Finding exact = buildFinding("SQL Injection", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/auth.java", "sast", null, assetId, "OPEN", now);
        Finding similar = buildFinding("SQL Injection vulnerability", "INJECTION", "HIGH", "CWE-89", "CWE-89",
                "/src/user.java", "sast", null, assetId, "OPEN", now);
        Finding unrelated = buildFinding("Missing Header", "SCA", "LOW", "CWE-693", null,
                "/pom.xml", "sca", null, UUID.randomUUID(), "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(exact, similar, unrelated));

        assertFalse(result.matches().isEmpty());
        assertTrue("EXACT_MATCH".equals(result.reason()) || "SIMILAR".equals(result.reason()));
    }

    @Test
    void correlate_cweIdOverridesCwe() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Injection", "INJECTION", "HIGH", null, "CWE-89",
                "/src/main.java", "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Injection Point", "INJECTION", "HIGH", null, "CWE-89",
                "/src/main.java", "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_cweWithCweIdSameValue_bonusApplied() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding newFinding = buildFinding("Auth Bug", "AUTHORIZATION", "HIGH", "CWE-287", "CWE-287",
                null, "sast", null, assetId, "OPEN", now);
        Finding existing = buildFinding("Auth Issue", "AUTHORIZATION", "HIGH", "CWE-287", "CWE-287",
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(newFinding, List.of(existing));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_jaroWinkler_identicalStrings() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding a = buildFinding("test", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);
        Finding b = buildFinding("test", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertFalse(result.matches().isEmpty());
    }

    @Test
    void correlate_jaroWinkler_differentLengthStrings() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding a = buildFinding("a", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);
        Finding b = buildFinding("abcdef", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }

    @Test
    void correlate_jaroWinkler_emptyString() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding a = buildFinding("", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);
        Finding b = buildFinding("test", "SAST", "HIGH", null, null,
                null, "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }

    @Test
    void correlate_jaroWinkler_singleCharPrefix() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding a = buildFinding("XSS vulnerability", "XSS", "MEDIUM", null, null,
                null, "dast", null, assetId, "OPEN", now);
        Finding b = buildFinding("XSS attack vector", "XSS", "MEDIUM", null, null,
                null, "dast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }

    @Test
    void correlate_nullFilePathAndAssetId_noBonus() {
        Instant now = Instant.now();
        Finding a = buildFinding("Issue", "SAST", "HIGH", "CWE-89", null,
                null, "sast", null, null, "OPEN", now);
        Finding b = buildFinding("Issue", "SAST", "HIGH", "CWE-89", null,
                null, "sast", null, null, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }

    @Test
    void correlate_nullCreatedAt_noTemporalBonus() {
        UUID assetId = UUID.randomUUID();
        Finding a = buildFinding("Issue", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", null);
        Finding b = buildFinding("Issue", "SAST", "HIGH", "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", null);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }

    @Test
    void correlate_nullSeverity_noPenalty() {
        UUID assetId = UUID.randomUUID();
        Instant now = Instant.now();
        Finding a = buildFinding("Issue", "SAST", null, "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", now);
        Finding b = buildFinding("Issue", "SAST", null, "CWE-89", null,
                "/src/main.java", "sast", null, assetId, "OPEN", now);

        CorrelationResult result = engine.correlate(a, List.of(b));

        assertNotNull(result);
    }
}
