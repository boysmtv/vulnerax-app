package com.vulnerax.modules.organization;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class OrganizationEntityTest {

    // ─── Project ──────────────────────────────────────────────

    @Test
    void project_builder_allFields() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();

        Project p = Project.builder()
                .name("VulnScanner")
                .workspaceId(wsId)
                .organizationId(orgId)
                .description("Vulnerability scanning project")
                .criticality("CRITICAL")
                .status("ARCHIVED")
                .businessUnit("Security")
                .techLead("Alice")
                .securityChampion("Bob")
                .build();

        assertThat(p.getName()).isEqualTo("VulnScanner");
        assertThat(p.getWorkspaceId()).isEqualTo(wsId);
        assertThat(p.getOrganizationId()).isEqualTo(orgId);
        assertThat(p.getDescription()).isEqualTo("Vulnerability scanning project");
        assertThat(p.getCriticality()).isEqualTo("CRITICAL");
        assertThat(p.getStatus()).isEqualTo("ARCHIVED");
        assertThat(p.getBusinessUnit()).isEqualTo("Security");
        assertThat(p.getTechLead()).isEqualTo("Alice");
        assertThat(p.getSecurityChampion()).isEqualTo("Bob");
    }

    @Test
    void project_builder_defaults() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();

        Project p = Project.builder()
                .name("MinimalProject")
                .workspaceId(wsId)
                .organizationId(orgId)
                .build();

        assertThat(p.getCriticality()).isEqualTo("HIGH");
        assertThat(p.getStatus()).isEqualTo("ACTIVE");
        assertThat(p.getDescription()).isNull();
        assertThat(p.getBusinessUnit()).isNull();
        assertThat(p.getTechLead()).isNull();
        assertThat(p.getSecurityChampion()).isNull();
    }

    @Test
    void project_builder_overrideDefaults() {
        Project p = Project.builder()
                .name("CustomDefaults")
                .workspaceId(UUID.randomUUID())
                .organizationId(UUID.randomUUID())
                .criticality("LOW")
                .status("INACTIVE")
                .build();

        assertThat(p.getCriticality()).isEqualTo("LOW");
        assertThat(p.getStatus()).isEqualTo("INACTIVE");
    }

    @Test
    void project_setters() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();

        Project p = new Project();
        p.setName("SetterProject");
        p.setWorkspaceId(wsId);
        p.setOrganizationId(orgId);
        p.setDescription("via setters");
        p.setCriticality("MEDIUM");
        p.setStatus("DRAFT");
        p.setBusinessUnit("Engineering");
        p.setTechLead("Carol");
        p.setSecurityChampion("Dave");

        assertThat(p.getName()).isEqualTo("SetterProject");
        assertThat(p.getWorkspaceId()).isEqualTo(wsId);
        assertThat(p.getOrganizationId()).isEqualTo(orgId);
        assertThat(p.getDescription()).isEqualTo("via setters");
        assertThat(p.getCriticality()).isEqualTo("MEDIUM");
        assertThat(p.getStatus()).isEqualTo("DRAFT");
        assertThat(p.getBusinessUnit()).isEqualTo("Engineering");
        assertThat(p.getTechLead()).isEqualTo("Carol");
        assertThat(p.getSecurityChampion()).isEqualTo("Dave");
    }

    @Test
    void project_noArgsConstructor() {
        Project p = new Project();
        assertThat(p.getName()).isNull();
        assertThat(p.getWorkspaceId()).isNull();
        assertThat(p.getOrganizationId()).isNull();
        assertThat(p.getCriticality()).isEqualTo("HIGH");
        assertThat(p.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void project_allArgsConstructor() {
        UUID wsId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();

        Project p = new Project(
                "AllArgsProject", wsId, orgId, "desc",
                "CRITICAL", "ACTIVE", "BU", "Lead", "Champ"
        );

        assertThat(p.getName()).isEqualTo("AllArgsProject");
        assertThat(p.getWorkspaceId()).isEqualTo(wsId);
        assertThat(p.getOrganizationId()).isEqualTo(orgId);
        assertThat(p.getDescription()).isEqualTo("desc");
        assertThat(p.getCriticality()).isEqualTo("CRITICAL");
        assertThat(p.getStatus()).isEqualTo("ACTIVE");
        assertThat(p.getBusinessUnit()).isEqualTo("BU");
        assertThat(p.getTechLead()).isEqualTo("Lead");
        assertThat(p.getSecurityChampion()).isEqualTo("Champ");
    }

    @Test
    void project_extendsBaseEntity() {
        UUID id = UUID.randomUUID();
        Project p = Project.builder()
                .name("BaseTest")
                .workspaceId(UUID.randomUUID())
                .organizationId(UUID.randomUUID())
                .build();
        p.setId(id);

        assertThat(p.getId()).isEqualTo(id);
    }

    // ─── Workspace ────────────────────────────────────────────

    @Test
    void workspace_builder_allFields() {
        UUID orgId = UUID.randomUUID();

        Workspace ws = Workspace.builder()
                .name("Production")
                .organizationId(orgId)
                .description("Main workspace")
                .environment("STAGING")
                .build();

        assertThat(ws.getName()).isEqualTo("Production");
        assertThat(ws.getOrganizationId()).isEqualTo(orgId);
        assertThat(ws.getDescription()).isEqualTo("Main workspace");
        assertThat(ws.getEnvironment()).isEqualTo("STAGING");
    }

    @Test
    void workspace_builder_defaultEnvironment() {
        UUID orgId = UUID.randomUUID();

        Workspace ws = Workspace.builder()
                .name("DefaultEnv")
                .organizationId(orgId)
                .build();

        assertThat(ws.getEnvironment()).isEqualTo("PRODUCTION");
        assertThat(ws.getDescription()).isNull();
    }

    @Test
    void workspace_builder_overrideDefaultEnvironment() {
        Workspace ws = Workspace.builder()
                .name("DevWorkspace")
                .organizationId(UUID.randomUUID())
                .environment("DEV")
                .build();

        assertThat(ws.getEnvironment()).isEqualTo("DEV");
    }

    @Test
    void workspace_setters() {
        UUID orgId = UUID.randomUUID();

        Workspace ws = new Workspace();
        ws.setName("SetterWorkspace");
        ws.setOrganizationId(orgId);
        ws.setDescription("via setters");
        ws.setEnvironment("QA");

        assertThat(ws.getName()).isEqualTo("SetterWorkspace");
        assertThat(ws.getOrganizationId()).isEqualTo(orgId);
        assertThat(ws.getDescription()).isEqualTo("via setters");
        assertThat(ws.getEnvironment()).isEqualTo("QA");
    }

    @Test
    void workspace_noArgsConstructor() {
        Workspace ws = new Workspace();
        assertThat(ws.getName()).isNull();
        assertThat(ws.getOrganizationId()).isNull();
        assertThat(ws.getDescription()).isNull();
        assertThat(ws.getEnvironment()).isEqualTo("PRODUCTION");
    }

    @Test
    void workspace_allArgsConstructor() {
        UUID orgId = UUID.randomUUID();

        Workspace ws = new Workspace("AllArgs", orgId, "desc", "DR");
        assertThat(ws.getName()).isEqualTo("AllArgs");
        assertThat(ws.getOrganizationId()).isEqualTo(orgId);
        assertThat(ws.getDescription()).isEqualTo("desc");
        assertThat(ws.getEnvironment()).isEqualTo("DR");
    }

    @Test
    void workspace_extendsBaseEntity() {
        UUID id = UUID.randomUUID();
        Workspace ws = Workspace.builder()
                .name("BaseTest")
                .organizationId(UUID.randomUUID())
                .build();
        ws.setId(id);

        assertThat(ws.getId()).isEqualTo(id);
    }

    @Test
    void workspace_allEnvironmentValues() {
        String[] envs = {"DEV", "QA", "STAGING", "PRODUCTION", "DR"};
        for (String env : envs) {
            Workspace ws = Workspace.builder()
                    .name("WS-" + env)
                    .organizationId(UUID.randomUUID())
                    .environment(env)
                    .build();
            assertThat(ws.getEnvironment()).isEqualTo(env);
        }
    }
}
