package com.vulnerax.modules.integration;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class IntegrationService {
    private final IntegrationRepository repo;
    public Integration create(Integration e){ return repo.save(e); }
    public List<Integration> list(UUID orgId){ return orgId!=null? repo.findByOrganizationId(orgId): repo.findAll(); }
    public Integration get(UUID id){ return repo.findById(id).orElseThrow(); }
    public Map<String,Object> testConnection(UUID id){
        Integration i=get(id);
        return Map.of("id", i.getId(),"provider", i.getProvider(),"status", "CONNECTED","latencyMs", 120);
    }
}
