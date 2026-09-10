package com.vulnerax.modules.organization;

import com.vulnerax.common.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OrganizationService {
    private final OrganizationRepository orgRepo;
    private final WorkspaceRepository wsRepo;
    private final ProjectRepository projectRepo;

    public Page<Organization> listOrgs(Pageable p) { return orgRepo.findAll(p); }
    public Organization getOrg(UUID id) { return orgRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Organization not found")); }
    @Transactional
    public Organization createOrg(Organization o) {
        o.setSlug(o.getName().toLowerCase().replaceAll("[^a-z0-9]+","-"));
        return orgRepo.save(o);
    }
    public Page<Workspace> listWorkspaces(UUID orgId, Pageable p) { return wsRepo.findAll(p); }
    @Transactional
    public Workspace createWorkspace(Workspace w) { return wsRepo.save(w); }
    public Page<Project> listProjects(UUID orgId, Pageable p) { return projectRepo.findAll(p); }
    @Transactional
    public Project createProject(Project pr) { return projectRepo.save(pr); }
    public Project getProject(UUID id) { return projectRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Project not found")); }
}
