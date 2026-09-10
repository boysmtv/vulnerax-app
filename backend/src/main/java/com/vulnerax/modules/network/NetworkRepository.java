package com.vulnerax.modules.network;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface NetworkRepository extends JpaRepository<NetworkAsset, UUID> {
    List<NetworkAsset> findByProjectId(UUID projectId);
}
