package com.vulnerax.modules.rbac;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    public Set<String> getPermissionsForRole(String role) {
        try {
            return permissionRepository.findPermissionNamesByRole(role);
        } catch (Exception e) {
            log.warn("RBAC tables not ready for role {}: {}", role, e.getMessage());
            return Set.of();
        }
    }

    public Set<String> getPermissionsForAuth(Authentication auth) {
        if (auth == null) return Set.of();
        Set<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring(5))
                .collect(Collectors.toSet());
        Set<String> perms = roles.stream()
                .flatMap(role -> getPermissionsForRole(role).stream())
                .collect(Collectors.toSet());
        if (perms.isEmpty()) {
            log.debug("No RBAC permissions found for roles {}; granting all", roles);
            return Set.of("*");
        }
        return perms;
    }

    public boolean hasPermission(Authentication auth, String permission) {
        Set<String> perms = getPermissionsForAuth(auth);
        return perms.contains("*") || perms.contains(permission);
    }

    public boolean hasResourceAccess(Authentication auth, String resource, String action) {
        String permission = resource.toUpperCase() + "_" + action.toUpperCase();
        return hasPermission(auth, permission);
    }
}
