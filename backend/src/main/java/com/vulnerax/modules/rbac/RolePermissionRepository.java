package com.vulnerax.modules.rbac;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {
}
