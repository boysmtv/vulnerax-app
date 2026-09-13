package com.vulnerax.modules.rbac;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    @Query("SELECT p.name FROM RolePermission rp JOIN rp.permission p WHERE rp.role = :role")
    Set<String> findPermissionNamesByRole(String role);

    @Query("SELECT p FROM RolePermission rp JOIN rp.permission p WHERE rp.role = :role")
    List<Permission> findPermissionsByRole(String role);
}
