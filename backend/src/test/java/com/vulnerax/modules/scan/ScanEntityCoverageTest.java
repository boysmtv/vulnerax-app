package com.vulnerax.modules.scan;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ScanEntityCoverageTest {

    @Test
    void builder_allFields() {
        UUID id = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();

        Scan s = Scan.builder()
                .projectId(projectId)
                .organizationId(orgId)
                .scannerType("SAST")
                .scanType("url")
                .profile("STANDARD")
                .target("https://example.com")
                .targetUrl("https://example.com")
                .configJson("{\"key\":\"value\"}")
                .status("QUEUED")
                .initiatedBy("user@test.com")
                .assetId(assetId)
                .findingsCount(5)
                .build();
        s.setId(id);

        assertThat(s.getProjectId()).isEqualTo(projectId);
        assertThat(s.getOrganizationId()).isEqualTo(orgId);
        assertThat(s.getScannerType()).isEqualTo("SAST");
        assertThat(s.getScanType()).isEqualTo("url");
        assertThat(s.getProfile()).isEqualTo("STANDARD");
        assertThat(s.getTarget()).isEqualTo("https://example.com");
        assertThat(s.getTargetUrl()).isEqualTo("https://example.com");
        assertThat(s.getConfigJson()).contains("key");
        assertThat(s.getStatus()).isEqualTo("QUEUED");
        assertThat(s.getInitiatedBy()).isEqualTo("user@test.com");
        assertThat(s.getAssetId()).isEqualTo(assetId);
        assertThat(s.getFindingsCount()).isEqualTo(5);
        assertThat(s.getId()).isEqualTo(id);
    }

    @Test
    void noArgsConstructor() {
        Scan s = new Scan();
        assertThat(s).isNotNull();
    }

    @Test
    void setters() {
        Scan s = new Scan();
        UUID id = UUID.randomUUID();
        s.setId(id);
        s.setProjectId(UUID.randomUUID());
        s.setOrganizationId(UUID.randomUUID());
        s.setScannerType("DAST");
        s.setScanType("file");
        s.setProfile("DEEP");
        s.setTarget("file:///test");
        s.setTargetUrl("file:///test");
        s.setConfigJson("{}");
        s.setStatus("RUNNING");
        s.setInitiatedBy("admin");
        s.setAssetId(UUID.randomUUID());
        s.setFindingsCount(10);
        s.setStartedAt(java.time.Instant.now());
        s.setFinishedAt(java.time.Instant.now());
        s.setDurationMs(5000L);
        assertThat(s.getId()).isEqualTo(id);
        assertThat(s.getScannerType()).isEqualTo("DAST");
        assertThat(s.getDurationMs()).isEqualTo(5000L);
    }
}
