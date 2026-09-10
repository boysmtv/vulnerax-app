package com.vulnerax.modules.k8s;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class K8sService {
    private final K8sRepository repo;
    public K8sResource create(K8sResource k){
        if(k.getRiskJson()==null) k.setRiskJson("{\"rbac\":\"ClusterAdmin binding\",\"privilege\":\"privileged:true\",\"network\":\"No NetworkPolicy\"}");
        return repo.save(k);
    }
    public List<K8sResource> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public K8sResource get(UUID id){ return repo.findById(id).orElseThrow(); }
    public List<K8sResource> scanMock(UUID projectId){
        return List.of(
            K8sResource.builder().projectId(projectId).clusterName("prod-eks").namespace("production").kind("Deployment").name("payment-service").configurationJson("{\"privileged\":true,\"runAsRoot\":true}").build(),
            K8sResource.builder().projectId(projectId).clusterName("prod-eks").namespace("kube-system").kind("ClusterRole").name("cluster-admin").build()
        ).stream().map(this::create).toList();
    }
}
