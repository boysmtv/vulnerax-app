package com.vulnerax.modules.coverage;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class CoverageService {
    private final CoverageRepository repo;
    public SecurityCoverage upsert(SecurityCoverage c){ return repo.save(c); }
    public List<SecurityCoverage> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public Map<String,Object> summary(UUID projectId){
        var list=list(projectId);
        long tested=list.stream().filter(x -> !"NOT_TESTED".equals(x.getStatus())).count();
        return Map.of("totalDomains", list.size(),"tested", tested,"gap", list.size()-tested,"byStatus", list.stream().collect(java.util.stream.Collectors.groupingBy(e -> e.getStatus(), java.util.stream.Collectors.counting())));
    }
}
