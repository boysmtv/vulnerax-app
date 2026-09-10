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
        List<CloudResource> mocks=List.of(
            CloudResource.builder().projectId(projectId).provider("AWS").accountId("123456789").region("ap-southeast-1").service("S3").resourceType("Bucket").resourceId("acme-public-backup").name("public-backup").publicExposed(true).riskJson("{\"issue\":\"Public S3 bucket\"}").build(),
            CloudResource.builder().projectId(projectId).provider("AWS").accountId("123456789").region("us-east-1").service("IAM").resourceType("Role").resourceId("AdminRole").name("AdminRole").riskJson("{\"issue\":\"Wildcard * permission\"}").build(),
            CloudResource.builder().projectId(projectId).provider("GCP").accountId("acme-gcp").region("asia-southeast2").service("Compute").resourceType("VM").resourceId("vm-banking-01").name("vm-banking-01").build()
        );
        return mocks.stream().map(this::create).toList();
    }
}
