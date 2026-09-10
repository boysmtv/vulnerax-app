package com.vulnerax.modules.aillm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class AiLlmService {
    private final AiRepository repo;
    public AiAsset create(AiAsset e){ return repo.save(e); }
    public List<AiAsset> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public AiAsset get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
