package com.vulnerax.modules.cloud;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class CloudService {
    private final CloudRepository repo;
    public CloudResource create(CloudResource c){
        if(c.getRiskJson()==null) c.setRiskJson("{\"iam\":\"Least privilege\",\"network\":\"Public exposure check\",\"storage\":\"Encryption\"}");
        if(c.getComplianceJson()==null) c.setComplianceJson("{\"CIS\":\"1.1\",\"PCI\":\"4.0\"}");
        return repo.save(c);
    }
    public List<CloudResource> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public CloudResource get(UUID id){ return repo.findById(id).orElseThrow(); }
    public List<CloudResource> scanMock(UUID projectId){
        throw new com.vulnerax.common.exception.BusinessException("Real cloud discovery required: configure AWS/Azure/GCP connector credentials. Mock scan disabled per 'hilangkan semua data mock'.");
    }
}
