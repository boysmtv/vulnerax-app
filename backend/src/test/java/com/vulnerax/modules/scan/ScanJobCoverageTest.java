package com.vulnerax.modules.scan;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ScanJobCoverageTest {

    @Test
    void builder_allFields() {
        UUID id = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        ScanJob j = ScanJob.builder()
                .scanId(scanId)
                .scannerPlugin("sast-plugin")
                .status("COMPLETED")
                .progress(100)
                .workerId("worker-1")
                .logs("Completed: 5 findings")
                .resultJson("{\"findings\":5}")
                .build();
        j.setId(id);

        assertThat(j.getScanId()).isEqualTo(scanId);
        assertThat(j.getScannerPlugin()).isEqualTo("sast-plugin");
        assertThat(j.getStatus()).isEqualTo("COMPLETED");
        assertThat(j.getProgress()).isEqualTo(100);
        assertThat(j.getWorkerId()).isEqualTo("worker-1");
        assertThat(j.getLogs()).contains("5 findings");
        assertThat(j.getResultJson()).contains("5");
        assertThat(j.getId()).isEqualTo(id);
    }

    @Test
    void noArgsConstructor() {
        ScanJob j = new ScanJob();
        assertThat(j).isNotNull();
    }

    @Test
    void setters() {
        ScanJob j = new ScanJob();
        UUID id = UUID.randomUUID();
        j.setId(id);
        j.setScanId(UUID.randomUUID());
        j.setScannerPlugin("dast-plugin");
        j.setStatus("RUNNING");
        j.setProgress(50);
        j.setWorkerId("worker-2");
        j.setLogs("Running...");
        j.setResultJson("{}");
        assertThat(j.getId()).isEqualTo(id);
        assertThat(j.getProgress()).isEqualTo(50);
    }
}
