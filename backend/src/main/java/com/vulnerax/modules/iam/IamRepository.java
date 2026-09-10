package com.vulnerax.modules.iam;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface IamRepository extends JpaRepository<IamResource, UUID> {
    List<IamResource> findByProjectId(UUID projectId);
}
