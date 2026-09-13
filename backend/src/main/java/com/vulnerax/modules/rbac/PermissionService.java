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
        return permissionRepository.findPermissionNamesByRole(role);
    }

    public Set<String> getPermissionsForAuth(Authentication auth) {
        if (auth == null) return Set.of();
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring(5))
                .flatMap(role -> getPermissionsForRole(role).stream())
                .collect(Collectors.toSet());
    }

    public boolean hasPermission(Authentication auth, String permission) {
        return getPermissionsForAuth(auth).contains(permission);
    }

    public boolean hasResourceAccess(Authentication auth, String resource, String action) {
        String permission = resource.toUpperCase() + "_" + action.toUpperCase();
        return hasPermission(auth, permission);
    }
}
