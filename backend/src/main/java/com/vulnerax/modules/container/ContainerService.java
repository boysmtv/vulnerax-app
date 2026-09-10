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
        return List.of(
            ContainerImage.builder().projectId(projectId).imageName("payment-service").tag("v2.4.1").baseImage("eclipse-temurin:17-jre").digest("sha256:abc").cveJson("[{\"cve\":\"CVE-2023-44487\",\"severity\":\"HIGH\"}]").misconfigJson("{\"runningAsRoot\":true}").build()
        ).stream().map(this::create).toList();
    }
}
