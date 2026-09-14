package com.vulnerax.modules.reporting;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ReportControllerGenReqTest {

    @Test
    void genReq_noArgsConstructor() {
        ReportController.GenReq gr = new ReportController.GenReq();
        assertThat(gr).isNotNull();
        assertThat(gr.getProjectId()).isNull();
        assertThat(gr.getType()).isNull();
        assertThat(gr.getTitle()).isNull();
        assertThat(gr.getFormat()).isNull();
    }

    @Test
    void genReq_settersAndGetters() {
        ReportController.GenReq gr = new ReportController.GenReq();
        UUID pid = UUID.randomUUID();
        gr.setProjectId(pid);
        gr.setType("EXECUTIVE");
        gr.setTitle("Q1 Report");
        gr.setFormat("PDF");
        assertThat(gr.getProjectId()).isEqualTo(pid);
        assertThat(gr.getType()).isEqualTo("EXECUTIVE");
        assertThat(gr.getTitle()).isEqualTo("Q1 Report");
        assertThat(gr.getFormat()).isEqualTo("PDF");
    }

    @Test
    void genReq_equals_sameValues() {
        UUID pid = UUID.randomUUID();
        ReportController.GenReq gr1 = new ReportController.GenReq();
        gr1.setProjectId(pid);
        gr1.setType("TECHNICAL");
        gr1.setTitle("Report");
        gr1.setFormat("HTML");
        ReportController.GenReq gr2 = new ReportController.GenReq();
        gr2.setProjectId(pid);
        gr2.setType("TECHNICAL");
        gr2.setTitle("Report");
        gr2.setFormat("HTML");
        assertThat(gr1).isEqualTo(gr2);
        assertThat(gr1.hashCode()).isEqualTo(gr2.hashCode());
    }

    @Test
    void genReq_equals_differentValues() {
        ReportController.GenReq gr1 = new ReportController.GenReq();
        gr1.setType("EXECUTIVE");
        ReportController.GenReq gr2 = new ReportController.GenReq();
        gr2.setType("TECHNICAL");
        assertThat(gr1).isNotEqualTo(gr2);
    }

    @Test
    void genReq_toString_containsFields() {
        ReportController.GenReq gr = new ReportController.GenReq();
        gr.setType("COMPLIANCE");
        String str = gr.toString();
        assertThat(str).contains("COMPLIANCE");
    }

    @Test
    void genReq_equals_null() {
        ReportController.GenReq gr = new ReportController.GenReq();
        gr.setType("TEST");
        assertThat(gr).isNotEqualTo(null);
    }

    @Test
    void genReq_equals_differentType() {
        ReportController.GenReq gr = new ReportController.GenReq();
        gr.setType("TEST");
        assertThat(gr).isNotEqualTo("string");
    }
}
