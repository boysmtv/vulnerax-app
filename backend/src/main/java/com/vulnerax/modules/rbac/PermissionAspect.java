package com.vulnerax.modules.rbac;

import com.vulnerax.common.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class PermissionAspect {

    private final PermissionService permissionService;

    @Around("@annotation(requirePermission)")
    public Object checkPermission(ProceedingJoinPoint joinPoint, RequirePermission requirePermission) throws Throwable {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new BusinessException("Not authenticated");
        }

        String permission = requirePermission.value();
        if (!permissionService.hasPermission(auth, permission)) {
            log.warn("User {} denied access: required permission {}", auth.getName(), permission);
            throw new BusinessException("Access denied: requires permission " + permission);
        }

        return joinPoint.proceed();
    }
}
