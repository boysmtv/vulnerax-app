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
        throw new com.vulnerax.common.exception.BusinessException("Real K8s discovery required: configure kubeconfig and RBAC. Mock scan disabled.");
    }
}
