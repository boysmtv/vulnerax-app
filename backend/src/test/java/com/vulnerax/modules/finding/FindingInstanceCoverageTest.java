package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindingInstanceCoverageTest {

    @Test
    void builder_allFields() {
        UUID findingId = UUID.randomUUID();

        FindingInstance fi = FindingInstance.builder()
                .findingId(findingId)
                .assetName("api.example.com")
                .location("src/main.java:42")
                .scanner("SAST")
                .evidence("evidence data")
                .fingerprint("fp123")
                .build();
        fi.setId(UUID.randomUUID());

        assertThat(fi.getFindingId()).isEqualTo(findingId);
        assertThat(fi.getAssetName()).isEqualTo("api.example.com");
        assertThat(fi.getLocation()).isEqualTo("src/main.java:42");
        assertThat(fi.getScanner()).isEqualTo("SAST");
        assertThat(fi.getEvidence()).isEqualTo("evidence data");
        assertThat(fi.getFingerprint()).isEqualTo("fp123");
        assertThat(fi.getId()).isNotNull();
    }

    @Test
    void noArgsConstructor() {
        FindingInstance fi = new FindingInstance();
        assertThat(fi).isNotNull();
    }

    @Test
    void setters() {
        FindingInstance fi = new FindingInstance();
        UUID id = UUID.randomUUID();
        fi.setId(id);
        fi.setFindingId(UUID.randomUUID());
        fi.setAssetName("test");
        fi.setLocation("endpoint");
        fi.setScanner("DAST");
        fi.setEvidence("data");
        fi.setFingerprint("fp");
        assertThat(fi.getId()).isEqualTo(id);
        assertThat(fi.getAssetName()).isEqualTo("test");
    }
}
