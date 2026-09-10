package com.vulnerax.modules.iam;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class IamService {
    private final IamRepository repo;
    public IamResource create(IamResource e){ return repo.save(e); }
    public List<IamResource> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public IamResource get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
