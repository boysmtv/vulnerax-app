package com.vulnerax.modules.k8s;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface K8sRepository extends JpaRepository<K8sResource, UUID> { List<K8sResource> findByProjectId(UUID projectId); }
