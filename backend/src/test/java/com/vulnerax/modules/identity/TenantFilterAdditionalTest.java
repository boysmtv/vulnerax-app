package com.vulnerax.modules.identity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Optional;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TenantFilterAdditionalTest {

    @Mock UserRepository userRepository;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain filterChain;

    @InjectMocks TenantFilter filter;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
    }

    @Test
    void doFilterInternal_noAuthHeader_callsChainAndClearsContext() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn(null);
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        assert TenantContext.getOrganizationId() == null;
    }

    @Test
    void doFilterInternal_emptyAuthHeader_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_nonBearerHeader_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Basic abc123");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_invalidJwt_callsChainAndClearsContext() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Bearer invalid-jwt-token");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        assert TenantContext.getOrganizationId() == null;
    }

    @Test
    void doFilterInternal_contextAlwaysCleared() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn(null);
        TenantContext.set(java.util.UUID.randomUUID(), null, "test@test.com");
        filter.doFilterInternal(request, response, filterChain);
        assert TenantContext.getOrganizationId() == null;
    }
}
