package com.vulnerax.modules.organization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnerax.common.PageResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(OrganizationController.class)
@AutoConfigureMockMvc(addFilters = false)
class OrganizationControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @MockBean OrganizationService service;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    private Organization buildOrg(String name) {
        Organization o = Organization.builder().name(name).slug(name.toLowerCase().replaceAll("[^a-z0-9]+", "-")).build();
        o.setId(UUID.randomUUID());
        return o;
    }

    private Workspace buildWorkspace(String name, UUID orgId) {
        Workspace w = Workspace.builder().name(name).organizationId(orgId).build();
        w.setId(UUID.randomUUID());
        return w;
    }

    private Project buildProject(String name, UUID orgId, UUID wsId) {
        Project p = Project.builder().name(name).organizationId(orgId).workspaceId(wsId).build();
        p.setId(UUID.randomUUID());
        return p;
    }

    @Test
    void listOrgs_returnsPage() throws Exception {
        when(service.listOrgs(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(buildOrg("Acme"))));
        mvc.perform(get("/api/v1/organizations"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].name").value("Acme"));
    }

    @Test
    void createOrg_creates() throws Exception {
        Organization o = buildOrg("New Corp");
        when(service.createOrg(any(Organization.class))).thenReturn(o);
        mvc.perform(post("/api/v1/organizations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("name", "New Corp"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("New Corp"));
    }

    @Test
    void getOrg_returnsOrg() throws Exception {
        UUID id = UUID.randomUUID();
        Organization o = buildOrg("Test Org");
        o.setId(id);
        when(service.getOrg(id)).thenReturn(o);
        mvc.perform(get("/api/v1/organizations/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Test Org"));
    }

    @Test
    void createWorkspace_creates() throws Exception {
        UUID orgId = UUID.randomUUID();
        Workspace w = buildWorkspace("Prod", orgId);
        when(service.createWorkspace(any(Workspace.class))).thenReturn(w);
        mvc.perform(post("/api/v1/workspaces")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("name", "Prod", "organizationId", orgId.toString()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Prod"));
    }

    @Test
    void listWorkspaces_returnsPage() throws Exception {
        UUID orgId = UUID.randomUUID();
        when(service.listWorkspaces(eq(orgId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(buildWorkspace("Prod", orgId))));
        mvc.perform(get("/api/v1/workspaces").param("organizationId", orgId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].name").value("Prod"));
    }

    @Test
    void createProject_creates() throws Exception {
        UUID orgId = UUID.randomUUID();
        UUID wsId = UUID.randomUUID();
        Project p = buildProject("Web App", orgId, wsId);
        when(service.createProject(any(Project.class))).thenReturn(p);
        mvc.perform(post("/api/v1/projects")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("name", "Web App", "organizationId", orgId.toString(), "workspaceId", wsId.toString()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Web App"));
    }

    @Test
    void listProjects_returnsPage() throws Exception {
        UUID orgId = UUID.randomUUID();
        when(service.listProjects(eq(orgId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(buildProject("API", orgId, UUID.randomUUID()))));
        mvc.perform(get("/api/v1/projects").param("organizationId", orgId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].name").value("API"));
    }

    @Test
    void listProjects_nullOrgId_returnsAll() throws Exception {
        when(service.listProjects(isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/projects"))
                .andExpect(status().isOk());
    }

    @Test
    void getProject_returnsProject() throws Exception {
        UUID id = UUID.randomUUID();
        Project p = buildProject("Test", UUID.randomUUID(), UUID.randomUUID());
        p.setId(id);
        when(service.getProject(id)).thenReturn(p);
        mvc.perform(get("/api/v1/projects/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Test"));
    }

    @Test
    void listOrgs_emptyPage() throws Exception {
        when(service.listOrgs(any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/organizations"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content", hasSize(0)));
    }

    @Test
    void createOrg_withDescription() throws Exception {
        Organization o = buildOrg("Corp");
        o.setDescription("A corporation");
        when(service.createOrg(any(Organization.class))).thenReturn(o);
        mvc.perform(post("/api/v1/organizations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("name", "Corp", "description", "A corporation"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.description").value("A corporation"));
    }

    @Test
    void createWorkspace_withDescription() throws Exception {
        UUID orgId = UUID.randomUUID();
        Workspace w = buildWorkspace("Dev", orgId);
        w.setDescription("Dev workspace");
        when(service.createWorkspace(any(Workspace.class))).thenReturn(w);
        mvc.perform(post("/api/v1/workspaces")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("name", "Dev", "organizationId", orgId.toString(), "description", "Dev workspace"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.description").value("Dev workspace"));
    }

    @Test
    void createProject_withAllFields() throws Exception {
        UUID orgId = UUID.randomUUID();
        UUID wsId = UUID.randomUUID();
        Project p = buildProject("Full Project", orgId, wsId);
        p.setDescription("Full test");
        p.setCriticality("CRITICAL");
        p.setTechLead("lead@test.com");
        when(service.createProject(any(Project.class))).thenReturn(p);
        String body = om.writeValueAsString(java.util.Map.of(
                "name", "Full Project", "organizationId", orgId.toString(),
                "workspaceId", wsId.toString(), "description", "Full test",
                "criticality", "CRITICAL", "techLead", "lead@test.com"
        ));
        mvc.perform(post("/api/v1/projects")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.criticality").value("CRITICAL"));
    }

    @Test
    void listWorkspaces_emptyList() throws Exception {
        UUID orgId = UUID.randomUUID();
        when(service.listWorkspaces(eq(orgId), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/workspaces").param("organizationId", orgId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content", hasSize(0)));
    }

    @Test
    void listProjects_emptyList() throws Exception {
        UUID orgId = UUID.randomUUID();
        when(service.listProjects(eq(orgId), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/projects").param("organizationId", orgId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content", hasSize(0)));
    }
}
