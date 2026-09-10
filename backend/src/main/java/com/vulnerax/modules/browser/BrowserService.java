package com.vulnerax.modules.browser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class BrowserService {
    private final BrowserRepository repo;
    public BrowserExtension create(BrowserExtension e){ return repo.save(e); }
    public List<BrowserExtension> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public BrowserExtension get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
