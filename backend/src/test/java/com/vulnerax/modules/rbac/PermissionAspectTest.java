package com.vulnerax.modules.rbac;

import com.vulnerax.common.exception.BusinessException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.annotation.RetentionPolicy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PermissionAspectTest {

    @Mock PermissionService permissionService;
    @Mock ProceedingJoinPoint joinPoint;
    @InjectMocks PermissionAspect aspect;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private RequirePermission stubAnnotation(String permission) {
        RequirePermission ann = mock(RequirePermission.class);
        when(ann.value()).thenReturn(permission);
        return ann;
    }

    // --- checkPermission ---

    @Test
    void checkPermission_whenAuthIsNull_throwsBusinessException() {
        SecurityContextHolder.clearContext();
        RequirePermission ann = mock(RequirePermission.class);

        assertThatThrownBy(() -> aspect.checkPermission(joinPoint, ann))
                .isInstanceOf(BusinessException.class)
                .hasMessage("Not authenticated");

        verifyNoInteractions(joinPoint);
    }

    @Test
    void checkPermission_whenPermissionDenied_throwsBusinessException() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "user@test.com", null, java.util.List.of(new SimpleGrantedAuthority("ROLE_VIEWER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        RequirePermission ann = stubAnnotation("ASSET_DELETE");

        when(permissionService.hasPermission(auth, "ASSET_DELETE")).thenReturn(false);

        assertThatThrownBy(() -> aspect.checkPermission(joinPoint, ann))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("Access denied")
                .hasMessageContaining("ASSET_DELETE");

        verifyNoInteractions(joinPoint);
    }

    @Test
    void checkPermission_whenPermissionGranted_proceeds() throws Throwable {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "admin@test.com", null, java.util.List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        RequirePermission ann = stubAnnotation("ASSET_READ");

        when(permissionService.hasPermission(auth, "ASSET_READ")).thenReturn(true);
        when(joinPoint.proceed()).thenReturn("ok");

        Object result = aspect.checkPermission(joinPoint, ann);

        assertThat(result).isEqualTo("ok");
        verify(joinPoint).proceed();
    }

    @Test
    void checkPermission_whenWildcardPermission_proceeds() throws Throwable {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "superadmin@test.com", null, java.util.List.of(new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        RequirePermission ann = stubAnnotation("ANYTHING");

        when(permissionService.hasPermission(auth, "ANYTHING")).thenReturn(true);
        when(joinPoint.proceed()).thenReturn("proceed");

        Object result = aspect.checkPermission(joinPoint, ann);

        assertThat(result).isEqualTo("proceed");
        verify(joinPoint).proceed();
    }

    // --- RequirePermission annotation ---

    @Test
    void RequirePermission_annotation_hasCorrectRetention() {
        RetentionPolicy retention = RequirePermission.class.getAnnotation(java.lang.annotation.Retention.class).value();
        assertThat(retention).isEqualTo(RetentionPolicy.RUNTIME);
    }

    @Test
    void RequirePermission_annotation_canBeAppliedToMethod() {
        java.lang.annotation.ElementType[] targets = RequirePermission.class.getAnnotation(java.lang.annotation.Target.class).value();
        assertThat(targets).contains(java.lang.annotation.ElementType.METHOD);
    }

    @Test
    void RequirePermission_annotation_canBeAppliedToType() {
        java.lang.annotation.ElementType[] targets = RequirePermission.class.getAnnotation(java.lang.annotation.Target.class).value();
        assertThat(targets).contains(java.lang.annotation.ElementType.TYPE);
    }
}
