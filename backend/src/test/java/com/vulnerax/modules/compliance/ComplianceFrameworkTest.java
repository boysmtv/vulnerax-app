package com.vulnerax.modules.compliance;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ComplianceFrameworkTest {

    @Test
    void builder_allFields() {
        ComplianceFramework fw = ComplianceFramework.builder()
                .name("NIST CSF")
                .version("2.0")
                .description("NIST Cybersecurity Framework")
                .type("REGULATION")
                .controlsJson("[\"ID.AM\",\"ID.RA\"]")
                .mappingJson("{\"ID.AM\":\"asset-management\"}")
                .build();

        assertThat(fw.getName()).isEqualTo("NIST CSF");
        assertThat(fw.getVersion()).isEqualTo("2.0");
        assertThat(fw.getDescription()).isEqualTo("NIST Cybersecurity Framework");
        assertThat(fw.getType()).isEqualTo("REGULATION");
        assertThat(fw.getControlsJson()).isEqualTo("[\"ID.AM\",\"ID.RA\"]");
        assertThat(fw.getMappingJson()).isEqualTo("{\"ID.AM\":\"asset-management\"}");
    }

    @Test
    void builder_defaults() {
        ComplianceFramework fw = ComplianceFramework.builder()
                .name("ISO 27001")
                .version("2022")
                .build();

        assertThat(fw.getType()).isEqualTo("STANDARD");
        assertThat(fw.getControlsJson()).isEqualTo("[]");
        assertThat(fw.getMappingJson()).isEqualTo("{}");
        assertThat(fw.getDescription()).isNull();
    }

    @Test
    void gettersSetters() {
        ComplianceFramework fw = new ComplianceFramework();

        fw.setName("CIS Benchmark");
        assertThat(fw.getName()).isEqualTo("CIS Benchmark");

        fw.setVersion("v8.1");
        assertThat(fw.getVersion()).isEqualTo("v8.1");

        fw.setDescription("Center for Internet Security");
        assertThat(fw.getDescription()).isEqualTo("Center for Internet Security");

        fw.setType("FRAMEWORK");
        assertThat(fw.getType()).isEqualTo("FRAMEWORK");

        fw.setControlsJson("[\"IG1\",\"IG2\",\"IG3\"]");
        assertThat(fw.getControlsJson()).isEqualTo("[\"IG1\",\"IG2\",\"IG3\"]");

        fw.setMappingJson("{\"IG1\":\"implementation-group-1\"}");
        assertThat(fw.getMappingJson()).isEqualTo("{\"IG1\":\"implementation-group-1\"}");
    }

    @Test
    void builder_nullDescription() {
        ComplianceFramework fw = ComplianceFramework.builder()
                .name("SOC 2")
                .version("2017")
                .description(null)
                .build();

        assertThat(fw.getDescription()).isNull();
        assertThat(fw.getType()).isEqualTo("STANDARD");
    }

    @Test
    void noArgsConstructor_createsEmptyInstance() {
        ComplianceFramework fw = new ComplianceFramework();
        assertThat(fw.getName()).isNull();
        assertThat(fw.getVersion()).isNull();
        assertThat(fw.getType()).isEqualTo("STANDARD");
    }
}
