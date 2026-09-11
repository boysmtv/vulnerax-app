package com.vulnerax.modules.container;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class ContainerService {
    private final ContainerRepository repo;
    public ContainerImage create(ContainerImage c){ return repo.save(c); }
    public List<ContainerImage> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public ContainerImage get(UUID id){ return repo.findById(id).orElseThrow(); }
    public List<ContainerImage> scanMock(UUID projectId){
        throw new com.vulnerax.common.exception.BusinessException("Real container scan required: provide image digest and enable Trivy/Grype worker. Mock scan disabled.");
    }
}
