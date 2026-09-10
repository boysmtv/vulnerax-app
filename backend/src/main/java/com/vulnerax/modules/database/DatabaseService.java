package com.vulnerax.modules.database;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class DatabaseService {
    private final DatabaseRepository repo;
    public DatabaseAsset create(DatabaseAsset e){ return repo.save(e); }
    public List<DatabaseAsset> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public DatabaseAsset get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
