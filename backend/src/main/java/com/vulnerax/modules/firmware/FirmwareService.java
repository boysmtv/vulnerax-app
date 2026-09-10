package com.vulnerax.modules.firmware;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class FirmwareService {
    private final FirmwareRepository repo;
    public FirmwareAsset create(FirmwareAsset e){ return repo.save(e); }
    public List<FirmwareAsset> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public FirmwareAsset get(UUID id){ return repo.findById(id).orElseThrow(); }
    public void delete(UUID id){ repo.delete(get(id)); }
}
