package com.vulnerax.modules.organization;

import com.vulnerax.common.exception.ResourceNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationServiceTest {

    @Mock OrganizationRepository orgRepo;
    @Mock WorkspaceRepository wsRepo;
    @Mock ProjectRepository projectRepo;
    @InjectMocks OrganizationService service;

    // listOrgs
    @Test
    void listOrgs_returnsPage() {
        when(orgRepo.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));
        var page = service.listOrgs(PageRequest.of(0, 10));
        assertThat(page).isNotNull();
        verify(orgRepo).findAll(any(PageRequest.class));
    }

    // getOrg
    @Test
    void getOrg_found() {
        UUID id = UUID.randomUUID();
        Organization org = Organization.builder().name("Acme").slug("acme").build();
        org.setId(id);
        when(orgRepo.findById(id)).thenReturn(Optional.of(org));
        assertThat(service.getOrg(id).getName()).isEqualTo("Acme");
    }

    @Test
    void getOrg_notFound_throwsException() {
        UUID id = UUID.randomUUID();
        when(orgRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.getOrg(id))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Organization not found");
    }

    // createOrg
    @Test
    void createOrg_setsSlugAndSaves() {
        Organization org = Organization.builder().name("My Org Name").build();
        Organization saved = Organization.builder().name("My Org Name").slug("my-org-name").build();
        saved.setId(UUID.randomUUID());
        when(orgRepo.save(any())).thenReturn(saved);
        var result = service.createOrg(org);
        assertThat(result.getSlug()).isEqualTo("my-org-name");
        verify(orgRepo).save(org);
    }

    @Test
    void createOrg_slugSpecialChars_cleaned() {
        Organization org = Organization.builder().name("Test@Org#123!").build();
        Organization saved = Organization.builder().name("Test@Org#123!").slug("test-org-123-").build();
        when(orgRepo.save(any())).thenReturn(saved);
        var result = service.createOrg(org);
        assertThat(result.getSlug()).isEqualTo("test-org-123-");
    }

    // listWorkspaces
    @Test
    void listWorkspaces_returnsPage() {
        UUID orgId = UUID.randomUUID();
        when(wsRepo.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));
        var page = service.listWorkspaces(orgId, PageRequest.of(0, 10));
        assertThat(page).isNotNull();
        verify(wsRepo).findAll(any(PageRequest.class));
    }

    // createWorkspace
    @Test
    void createWorkspace_saves() {
        Workspace ws = Workspace.builder().name("Dev").organizationId(UUID.randomUUID()).build();
        Workspace saved = Workspace.builder().name("Dev").organizationId(ws.getOrganizationId()).build();
        saved.setId(UUID.randomUUID());
        when(wsRepo.save(any())).thenReturn(saved);
        var result = service.createWorkspace(ws);
        assertThat(result.getId()).isNotNull();
    }

    // listProjects
    @Test
    void listProjects_returnsPage() {
        UUID orgId = UUID.randomUUID();
        when(projectRepo.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));
        var page = service.listProjects(orgId, PageRequest.of(0, 10));
        assertThat(page).isNotNull();
        verify(projectRepo).findAll(any(PageRequest.class));
    }

    // createProject
    @Test
    void createProject_saves() {
        Project pr = Project.builder().name("Backend").workspaceId(UUID.randomUUID()).organizationId(UUID.randomUUID()).build();
        Project saved = Project.builder().name("Backend").workspaceId(pr.getWorkspaceId()).organizationId(pr.getOrganizationId()).build();
        saved.setId(UUID.randomUUID());
        when(projectRepo.save(any())).thenReturn(saved);
        var result = service.createProject(pr);
        assertThat(result.getId()).isNotNull();
    }

    // getProject
    @Test
    void getProject_found() {
        UUID id = UUID.randomUUID();
        Project pr = Project.builder().name("Frontend").workspaceId(UUID.randomUUID()).organizationId(UUID.randomUUID()).build();
        pr.setId(id);
        when(projectRepo.findById(id)).thenReturn(Optional.of(pr));
        assertThat(service.getProject(id).getName()).isEqualTo("Frontend");
    }

    @Test
    void getProject_notFound_throwsException() {
        UUID id = UUID.randomUUID();
        when(projectRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.getProject(id))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Project not found");
    }
}
