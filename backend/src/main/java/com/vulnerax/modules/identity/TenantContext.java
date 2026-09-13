package com.vulnerax.modules.identity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class TenantContext {

    private static final ThreadLocal<TenantInfo> CURRENT = new ThreadLocal<>();

    public static TenantInfo get() {
        TenantInfo info = CURRENT.get();
        if (info == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof String email) {
                info = new TenantInfo(null, null, email);
            } else {
                info = new TenantInfo(null, null, "anonymous");
            }
        }
        return info;
    }

    public static UUID getOrganizationId() {
        return get().organizationId();
    }

    public static UUID getProjectId() {
        return get().projectId();
    }

    public static String getEmail() {
        return get().email();
    }

    public static void set(UUID organizationId, UUID projectId, String email) {
        CURRENT.set(new TenantInfo(organizationId, projectId, email));
    }

    public static void clear() {
        CURRENT.remove();
    }

    public record TenantInfo(UUID organizationId, UUID projectId, String email) {}
}
