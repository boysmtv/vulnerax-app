package com.vulnerax.modules.network;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class NetworkService {
    private final NetworkRepository repo;
    public NetworkAsset create(NetworkAsset e){ return repo.save(e); }
    public List<NetworkAsset> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public NetworkAsset get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
