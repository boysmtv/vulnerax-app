package com.vulnerax.modules.sbom;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class SbomService {
    private final SbomRepository repo;
    public Sbom create(Sbom s) {
        s.setVersion("1.0-" + System.currentTimeMillis());
        if (s.getContentJson()==null) s.setContentJson("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"components\":[]}");
        s.setComponentCount( (int)(Math.random()*50+10) );
        s.setVulnerableCount( (int)(Math.random()*5) );
        return repo.save(s);
    }
    public List<Sbom> list(UUID projectId) { return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public Sbom get(UUID id) { return repo.findById(id).orElseThrow(); }
    public Map<String,Object> diff(UUID a, UUID b) {
        Sbom sa = get(a), sb = get(b);
        return Map.of("a", sa.getComponentCount(), "b", sb.getComponentCount(), "delta", sb.getComponentCount()-sa.getComponentCount(), "newVulns", sb.getVulnerableCount());
    }
}
