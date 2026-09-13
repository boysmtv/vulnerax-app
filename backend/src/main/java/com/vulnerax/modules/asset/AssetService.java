package com.vulnerax.modules.asset;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.organization.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AssetService {
    private final AssetRepository repo;
    private final AuditService auditService;
    private final ProjectRepository projectRepo;

    public Page<Asset> list(UUID projectId, UUID orgId, String type, String search, Pageable p) {
        if (projectId != null) return repo.findByProjectId(projectId, p);
        if (orgId != null) return repo.findByOrganizationId(orgId, p);
        return repo.findAll(p);
    }

    public Asset get(UUID id) { return repo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Asset not found")); }

    @Transactional
    public Asset create(Asset a) {
        Asset saved = repo.save(a);
        auditService.log("ASSET_CREATED", "Asset", saved.getId().toString(), "Created asset " + saved.getName());
        return saved;
    }

    @Transactional
    public Asset createAsset(String name, String type, String owner) {
        Asset a = Asset.builder()
                .name(name)
                .type(type)
                .identifier(name)
                .owner(owner)
                .criticality("MEDIUM")
                .internetExposed(name.startsWith("http"))
                .status("ACTIVE")
                .build();
        return create(a);
    }

    @Transactional
    public Asset update(UUID id, Asset patch) {
        Asset cur = get(id);
        if (patch.getName()!=null) cur.setName(patch.getName());
        if (patch.getCriticality()!=null) cur.setCriticality(patch.getCriticality());
        if (patch.getInternetExposed()!=null) cur.setInternetExposed(patch.getInternetExposed());
        if (patch.getStatus()!=null) cur.setStatus(patch.getStatus());
        if (patch.getOwner()!=null) cur.setOwner(patch.getOwner());
        if (patch.getTeam()!=null) cur.setTeam(patch.getTeam());
        if (patch.getTags()!=null) cur.setTags(patch.getTags());
        if (patch.getTechnology()!=null) cur.setTechnology(patch.getTechnology());
        return repo.save(cur);
    }

    @Transactional
    public void delete(UUID id) { repo.delete(get(id)); }

    public Map<String,Object> stats(UUID projectId) {
        long total = projectId!=null? repo.countByProjectId(projectId): repo.count();
        long exposed = repo.countByInternetExposedTrue();
        List<Object[]> byType = repo.countByType();
        List<Object[]> byCrit = repo.countByCriticality();
        Map<String,Object> m = new HashMap<>();
        m.put("total", total);
        m.put("internetExposed", exposed);
        m.put("byType", byType.stream().collect(Collectors.toMap(a->(String)a[0], a->(Long)a[1])));
        m.put("byCriticality", byCrit.stream().collect(Collectors.toMap(a->(String)a[0], a->(Long)a[1])));
        m.put("discoveryDelta", computeDelta(projectId));
        return m;
    }

    private Map<String,Object> computeDelta(UUID projectId) {
        // Simple delta: compares assets created in last 24h vs previous
        List<Asset> all = projectId!=null? repo.findByProjectId(projectId): repo.findAll();
        long newLast24h = all.stream().filter(a-> a.getCreatedAt()!=null && a.getCreatedAt().isAfter(Instant.now().minusSeconds(86400))).count();
        return Map.of("newLast24h", newLast24h, "previousTotal", all.size()-newLast24h);
    }

    public List<Asset> discoverMock(UUID projectId, String source) {
        // Mock removed per request "hilangkan semua data mock" — real discovery must be performed via authorized connectors
        // Return empty and require caller to integrate real discovery sources (GitHub/AWS/DNS/K8s). No example.com dummy.
        if (!"REAL".equalsIgnoreCase(source)) {
            throw new com.vulnerax.common.exception.BusinessException("Real discovery required: provide source=REAL with valid connector credentials (GitHub/AWS/DNS/K8s). Mock discovery disabled.");
        }
        // REAL path: if source==REAL, perform actual discovery (currently returns empty until connectors configured)
        // Future: query GitHub API, AWS Resource Groups, DNS enumeration, K8s API
        return List.of();
    }
}
