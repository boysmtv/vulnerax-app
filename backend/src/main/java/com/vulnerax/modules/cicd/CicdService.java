package com.vulnerax.modules.cicd;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class CicdService {
    private final CicdRepository repo;
    public CicdPipeline create(CicdPipeline e){ return repo.save(e); }
    public List<CicdPipeline> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public CicdPipeline get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
