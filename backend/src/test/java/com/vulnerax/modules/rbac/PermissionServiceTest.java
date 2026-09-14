package com.vulnerax.modules.rbac;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock PermissionRepository permissionRepository;
    @InjectMocks PermissionService service;

    private Authentication authWithRoles(String... roles) {
        var authorities = new java.util.ArrayList<SimpleGrantedAuthority>();
        for (String r : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        }
        return new UsernamePasswordAuthenticationToken("user", null, authorities);
    }

    // getPermissionsForRole
    @Test
    void getPermissionsForRole_returnsPermissions() {
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("USER_READ", "USER_WRITE"));
        var perms = service.getPermissionsForRole("ADMIN");
        assertThat(perms).containsExactlyInAnyOrder("USER_READ", "USER_WRITE");
    }

    @Test
    void getPermissionsForRole_exceptionReturnsEmptySet() {
        when(permissionRepository.findPermissionNamesByRole("BAD")).thenThrow(new RuntimeException("table missing"));
        var perms = service.getPermissionsForRole("BAD");
        assertThat(perms).isEmpty();
    }

    @Test
    void getPermissionsForRole_noPermissionsReturnsEmptySet() {
        when(permissionRepository.findPermissionNamesByRole("GUEST")).thenReturn(Set.of());
        var perms = service.getPermissionsForRole("GUEST");
        assertThat(perms).isEmpty();
    }

    // getPermissionsForAuth
    @Test
    void getPermissionsForAuth_nullAuth_returnsEmptySet() {
        var perms = service.getPermissionsForAuth(null);
        assertThat(perms).isEmpty();
    }

    @Test
    void getPermissionsForAuth_withRole_returnsPermissions() {
        Authentication auth = authWithRoles("ADMIN");
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("ASSET_READ"));
        var perms = service.getPermissionsForAuth(auth);
        assertThat(perms).contains("ASSET_READ");
    }

    @Test
    void getPermissionsForAuth_noRbacPerms_returnsWildcard() {
        Authentication auth = authWithRoles("DEVELOPER");
        when(permissionRepository.findPermissionNamesByRole("DEVELOPER")).thenReturn(Set.of());
        var perms = service.getPermissionsForAuth(auth);
        assertThat(perms).contains("*");
    }

    @Test
    void getPermissionsForAuth_multipleRoles_mergesPermissions() {
        Authentication auth = authWithRoles("ADMIN", "VIEWER");
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("ASSET_READ"));
        when(permissionRepository.findPermissionNamesByRole("VIEWER")).thenReturn(Set.of("FINDING_READ"));
        var perms = service.getPermissionsForAuth(auth);
        assertThat(perms).containsExactlyInAnyOrder("ASSET_READ", "FINDING_READ");
    }

    @Test
    void getPermissionsForAuth_filtersNonRoleAuthorities() {
        var authorities = java.util.List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("PERMISSION_RAW")
        );
        Authentication auth = new UsernamePasswordAuthenticationToken("user", null, authorities);
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("ASSET_READ"));
        var perms = service.getPermissionsForAuth(auth);
        assertThat(perms).contains("ASSET_READ");
        verify(permissionRepository, never()).findPermissionNamesByRole("PERMISSION_RAW");
    }

    // hasPermission
    @Test
    void hasPermission_withMatchingPermission_returnsTrue() {
        Authentication auth = authWithRoles("ADMIN");
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("ASSET_DELETE"));
        assertThat(service.hasPermission(auth, "ASSET_DELETE")).isTrue();
    }

    @Test
    void hasPermission_withoutPermission_returnsFalse() {
        Authentication auth = authWithRoles("VIEWER");
        when(permissionRepository.findPermissionNamesByRole("VIEWER")).thenReturn(Set.of("ASSET_READ"));
        assertThat(service.hasPermission(auth, "ASSET_DELETE")).isFalse();
    }

    @Test
    void hasPermission_wildcardAlwaysReturnsTrue() {
        Authentication auth = authWithRoles("SUPERADMIN");
        when(permissionRepository.findPermissionNamesByRole("SUPERADMIN")).thenReturn(Set.of("*"));
        assertThat(service.hasPermission(auth, "ANYTHING")).isTrue();
    }

    // hasResourceAccess
    @Test
    void hasResourceAccess_matchingResourceAction_returnsTrue() {
        Authentication auth = authWithRoles("ADMIN");
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("ASSET_DELETE"));
        assertThat(service.hasResourceAccess(auth, "asset", "delete")).isTrue();
    }

    @Test
    void hasResourceAccess_noMatching_returnsFalse() {
        Authentication auth = authWithRoles("VIEWER");
        when(permissionRepository.findPermissionNamesByRole("VIEWER")).thenReturn(Set.of("ASSET_READ"));
        assertThat(service.hasResourceAccess(auth, "asset", "delete")).isFalse();
    }

    @Test
    void hasResourceAccess_uppercasesResourceAndAction() {
        Authentication auth = authWithRoles("ADMIN");
        when(permissionRepository.findPermissionNamesByRole("ADMIN")).thenReturn(Set.of("FINDING_READ"));
        assertThat(service.hasResourceAccess(auth, "finding", "read")).isTrue();
        assertThat(service.hasResourceAccess(auth, "FINDING", "READ")).isTrue();
    }
}
