package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FindingControllerDtoTest {

    @Test
    void statusReq_noArgsConstructor() {
        FindingController.StatusReq sr = new FindingController.StatusReq();
        assertThat(sr).isNotNull();
        assertThat(sr.getStatus()).isNull();
        assertThat(sr.getComment()).isNull();
    }

    @Test
    void statusReq_settersAndGetters() {
        FindingController.StatusReq sr = new FindingController.StatusReq();
        sr.setStatus("RESOLVED");
        sr.setComment("Fixed the vulnerability");
        assertThat(sr.getStatus()).isEqualTo("RESOLVED");
        assertThat(sr.getComment()).isEqualTo("Fixed the vulnerability");
    }

    @Test
    void statusReq_equals_sameValues() {
        FindingController.StatusReq sr1 = new FindingController.StatusReq();
        sr1.setStatus("OPEN");
        sr1.setComment("c");
        FindingController.StatusReq sr2 = new FindingController.StatusReq();
        sr2.setStatus("OPEN");
        sr2.setComment("c");
        assertThat(sr1).isEqualTo(sr2);
        assertThat(sr1.hashCode()).isEqualTo(sr2.hashCode());
    }

    @Test
    void statusReq_equals_differentStatus() {
        FindingController.StatusReq sr1 = new FindingController.StatusReq();
        sr1.setStatus("OPEN");
        FindingController.StatusReq sr2 = new FindingController.StatusReq();
        sr2.setStatus("CLOSED");
        assertThat(sr1).isNotEqualTo(sr2);
    }

    @Test
    void statusReq_toString() {
        FindingController.StatusReq sr = new FindingController.StatusReq();
        sr.setStatus("IN_PROGRESS");
        sr.setComment("Working on it");
        String str = sr.toString();
        assertThat(str).contains("IN_PROGRESS");
    }
}
