package com.vulnerax.modules.policy;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyExceptionTest {

    private static Instant futureExpiration() {
        return Instant.now().plus(30, ChronoUnit.DAYS);
    }

    @Test
    void builder_allFields() {
        UUID policyId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();

        PolicyException ex = PolicyException.builder()
                .policyId(policyId)
                .findingId(findingId)
                .reason("Risk accepted for Q4")
                .owner("alice@example.com")
                .approver("bob@example.com")
                .expiration(futureExpiration())
                .compensatingControl("WAF rule applied")
                .status("APPROVED")
                .build();

        assertThat(ex.getPolicyId()).isEqualTo(policyId);
        assertThat(ex.getFindingId()).isEqualTo(findingId);
        assertThat(ex.getReason()).isEqualTo("Risk accepted for Q4");
        assertThat(ex.getOwner()).isEqualTo("alice@example.com");
        assertThat(ex.getApprover()).isEqualTo("bob@example.com");
        assertThat(ex.getExpiration()).isNotNull();
        assertThat(ex.getCompensatingControl()).isEqualTo("WAF rule applied");
        assertThat(ex.getStatus()).isEqualTo("APPROVED");
    }

    @Test
    void builder_defaults_statusIsPending() {
        PolicyException ex = PolicyException.builder()
                .policyId(UUID.randomUUID())
                .reason("Temporary bypass")
                .owner("owner@example.com")
                .approver("approver@example.com")
                .expiration(futureExpiration())
                .build();

        assertThat(ex.getStatus()).isEqualTo("PENDING");
        assertThat(ex.getFindingId()).isNull();
        assertThat(ex.getCompensatingControl()).isNull();
    }

    @Test
    void gettersSetters() {
        PolicyException ex = new PolicyException();

        UUID policyId = UUID.randomUUID();
        ex.setPolicyId(policyId);
        assertThat(ex.getPolicyId()).isEqualTo(policyId);

        UUID findingId = UUID.randomUUID();
        ex.setFindingId(findingId);
        assertThat(ex.getFindingId()).isEqualTo(findingId);

        ex.setReason("Audit finding");
        assertThat(ex.getReason()).isEqualTo("Audit finding");

        ex.setOwner("owner@test.com");
        assertThat(ex.getOwner()).isEqualTo("owner@test.com");

        ex.setApprover("manager@test.com");
        assertThat(ex.getApprover()).isEqualTo("manager@test.com");

        Instant exp = futureExpiration();
        ex.setExpiration(exp);
        assertThat(ex.getExpiration()).isEqualTo(exp);

        ex.setCompensatingControl("Network segmentation");
        assertThat(ex.getCompensatingControl()).isEqualTo("Network segmentation");

        ex.setStatus("REJECTED");
        assertThat(ex.getStatus()).isEqualTo("REJECTED");
    }

    @Test
    void builder_optionalFieldsNull() {
        PolicyException ex = PolicyException.builder()
                .policyId(UUID.randomUUID())
                .reason("No finding linked")
                .owner("owner@test.com")
                .approver("approver@test.com")
                .expiration(futureExpiration())
                .build();

        assertThat(ex.getFindingId()).isNull();
        assertThat(ex.getCompensatingControl()).isNull();
    }

    @Test
    void noArgsConstructor_createsEmptyInstance() {
        PolicyException ex = new PolicyException();
        assertThat(ex.getPolicyId()).isNull();
        assertThat(ex.getReason()).isNull();
        assertThat(ex.getStatus()).isEqualTo("PENDING");
    }
}
