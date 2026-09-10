package com.vulnerax.modules.iac;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class IacService {
    private final IacScanRepository repo;
    public IacScan create(IacScan e){ return repo.save(e); }
    public List<IacScan> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public IacScan get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
