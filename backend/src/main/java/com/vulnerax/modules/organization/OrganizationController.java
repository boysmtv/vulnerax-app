package com.vulnerax.modules.organization;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class OrganizationController {
    private final OrganizationService service;

    @GetMapping("/organizations")
    public ApiResponse<?> listOrgs(Pageable pageable) { return ApiResponse.ok(PageResponse.from(service.listOrgs(pageable))); }

    @PostMapping("/organizations")
    public ApiResponse<?> createOrg(@RequestBody Organization o) { return ApiResponse.ok(service.createOrg(o)); }

    @GetMapping("/organizations/{id}")
    public ApiResponse<?> getOrg(@PathVariable UUID id) { return ApiResponse.ok(service.getOrg(id)); }

    @PostMapping("/workspaces")
    public ApiResponse<?> createWs(@RequestBody Workspace w) { return ApiResponse.ok(service.createWorkspace(w)); }

    @GetMapping("/workspaces")
    public ApiResponse<?> listWs(@RequestParam UUID organizationId, Pageable pageable) { return ApiResponse.ok(PageResponse.from(service.listWorkspaces(organizationId, pageable))); }

    @PostMapping("/projects")
    public ApiResponse<?> createProject(@RequestBody Project p) { return ApiResponse.ok(service.createProject(p)); }

    @GetMapping("/projects")
    public ApiResponse<?> listProjects(@RequestParam(required = false) UUID organizationId, Pageable pageable) { return ApiResponse.ok(PageResponse.from(service.listProjects(organizationId, pageable))); }

    @GetMapping("/projects/{id}")
    public ApiResponse<?> getProject(@PathVariable UUID id) { return ApiResponse.ok(service.getProject(id)); }
}
