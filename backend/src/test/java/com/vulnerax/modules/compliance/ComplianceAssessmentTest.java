package com.vulnerax.modules.compliance;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ComplianceAssessmentTest {

    @Test
    void builder_allFields() {
        UUID projectId = UUID.randomUUID();
        UUID frameworkId = UUID.randomUUID();

        ComplianceAssessment a = ComplianceAssessment.builder()
                .projectId(projectId)
                .frameworkId(frameworkId)
                .status("COMPLETED")
                .resultsJson("[{\"control\":\"IG1\",\"status\":\"PASS\"}]")
                .score(87.5)
                .passed(17)
                .failed(2)
                .notApplicable(1)
                .notTested(0)
                .build();

        assertThat(a.getProjectId()).isEqualTo(projectId);
        assertThat(a.getFrameworkId()).isEqualTo(frameworkId);
        assertThat(a.getStatus()).isEqualTo("COMPLETED");
        assertThat(a.getResultsJson()).isEqualTo("[{\"control\":\"IG1\",\"status\":\"PASS\"}]");
        assertThat(a.getScore()).isEqualTo(87.5);
        assertThat(a.getPassed()).isEqualTo(17);
        assertThat(a.getFailed()).isEqualTo(2);
        assertThat(a.getNotApplicable()).isEqualTo(1);
        assertThat(a.getNotTested()).isEqualTo(0);
    }

    @Test
    void builder_defaults() {
        ComplianceAssessment a = ComplianceAssessment.builder()
                .projectId(UUID.randomUUID())
                .frameworkId(UUID.randomUUID())
                .build();

        assertThat(a.getStatus()).isEqualTo("IN_PROGRESS");
        assertThat(a.getResultsJson()).isEqualTo("[]");
        assertThat(a.getScore()).isEqualTo(0.0);
        assertThat(a.getPassed()).isEqualTo(0);
        assertThat(a.getFailed()).isEqualTo(0);
        assertThat(a.getNotApplicable()).isEqualTo(0);
        assertThat(a.getNotTested()).isEqualTo(0);
    }

    @Test
    void gettersSetters() {
        ComplianceAssessment a = new ComplianceAssessment();

        UUID projectId = UUID.randomUUID();
        a.setProjectId(projectId);
        assertThat(a.getProjectId()).isEqualTo(projectId);

        UUID frameworkId = UUID.randomUUID();
        a.setFrameworkId(frameworkId);
        assertThat(a.getFrameworkId()).isEqualTo(frameworkId);

        a.setStatus("FAILED");
        assertThat(a.getStatus()).isEqualTo("FAILED");

        a.setResultsJson("[{\"control\":\"IG3\",\"status\":\"FAIL\"}]");
        assertThat(a.getResultsJson()).isEqualTo("[{\"control\":\"IG3\",\"status\":\"FAIL\"}]");

        a.setScore(42.0);
        assertThat(a.getScore()).isEqualTo(42.0);

        a.setPassed(10);
        assertThat(a.getPassed()).isEqualTo(10);

        a.setFailed(5);
        assertThat(a.getFailed()).isEqualTo(5);

        a.setNotApplicable(3);
        assertThat(a.getNotApplicable()).isEqualTo(3);

        a.setNotTested(2);
        assertThat(a.getNotTested()).isEqualTo(2);
    }

    @Test
    void builder_minimalRequiredFields() {
        ComplianceAssessment a = ComplianceAssessment.builder()
                .projectId(UUID.randomUUID())
                .frameworkId(UUID.randomUUID())
                .build();

        assertThat(a.getProjectId()).isNotNull();
        assertThat(a.getFrameworkId()).isNotNull();
        assertThat(a.getStatus()).isEqualTo("IN_PROGRESS");
    }

    @Test
    void noArgsConstructor_createsEmptyInstance() {
        ComplianceAssessment a = new ComplianceAssessment();
        assertThat(a.getProjectId()).isNull();
        assertThat(a.getFrameworkId()).isNull();
        assertThat(a.getStatus()).isEqualTo("IN_PROGRESS");
        assertThat(a.getScore()).isEqualTo(0.0);
    }
}
