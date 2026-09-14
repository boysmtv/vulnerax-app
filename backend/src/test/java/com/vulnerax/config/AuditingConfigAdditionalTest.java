package com.vulnerax.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditingConfigAdditionalTest {

    private AuditingConfig config;

    @BeforeEach
    void setUp() {
        config = new AuditingConfig();
        SecurityContextHolder.clearContext();
    }

    @Test
    void auditorAware_returnsBean() {
        AuditorAware<String> auditor = config.auditorAware();
        assertThat(auditor).isNotNull();
    }

    @Test
    void auditorAware_noAuthentication_returnsSystem() {
        SecurityContextHolder.clearContext();
        AuditorAware<String> auditor = config.auditorAware();
        Optional<String> result = auditor.getCurrentAuditor();
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo("system");
    }

    @Test
    void auditorAware_unauthenticated_returnsSystem() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(auth);
        AuditorAware<String> auditor = config.auditorAware();
        Optional<String> result = auditor.getCurrentAuditor();
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo("system");
    }

    @Test
    void auditorAware_authenticated_returnsName() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getName()).thenReturn("admin@vulnerax.io");
        SecurityContextHolder.getContext().setAuthentication(auth);
        AuditorAware<String> auditor = config.auditorAware();
        Optional<String> result = auditor.getCurrentAuditor();
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo("admin@vulnerax.io");
    }
}
