package com.vulnerax.modules.identity;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TenantFilterTest {

    @Mock UserRepository userRepository;
    @Mock FilterChain filterChain;
    @InjectMocks TenantFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        TenantContext.clear();
    }

    @Test
    void doFilter_noAuthHeader_doesNotSetTenant() throws Exception {
        filter.doFilterInternal(request, response, filterChain);
        assertThat(TenantContext.getOrganizationId()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_validJwt_setsTenantContext() throws Exception {
        // Generate a valid JWT using the default secret
        String secret = "vulnerax-super-secret-jwt-key-must-be-at-least-64-chars-long-for-hs512-change-me";
        javax.crypto.SecretKey key = io.jsonwebtoken.security.Keys.hmacShaKeyFor(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String token = io.jsonwebtoken.Jwts.builder()
                .subject("admin@vulnerax.io")
                .signWith(key)
                .compact();

        request.addHeader("Authorization", "Bearer " + token);

        UUID orgId = UUID.randomUUID();
        User user = User.builder().email("admin@vulnerax.io").organizationId(orgId).build();
        when(userRepository.findByEmail("admin@vulnerax.io")).thenReturn(Optional.of(user));

        // Capture TenantContext during chain execution (finally block clears it after)
        final UUID[] capturedOrgId = new UUID[1];
        final String[] capturedEmail = new String[1];
        doAnswer(invocation -> {
            capturedOrgId[0] = TenantContext.getOrganizationId();
            capturedEmail[0] = TenantContext.getEmail();
            return null;
        }).when(filterChain).doFilter(request, response);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(capturedOrgId[0]).isEqualTo(orgId);
        assertThat(capturedEmail[0]).isEqualTo("admin@vulnerax.io");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_invalidJwt_doesNotSetTenant() throws Exception {
        request.addHeader("Authorization", "Bearer invalid.jwt.token");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(TenantContext.getOrganizationId()).isNull();
    }

    @Test
    void doFilter_userNotFound_doesNotSetTenant() throws Exception {
        String secret = "vulnerax-super-secret-jwt-key-must-be-at-least-64-chars-long-for-hs512-change-me";
        javax.crypto.SecretKey key = io.jsonwebtoken.security.Keys.hmacShaKeyFor(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String token = io.jsonwebtoken.Jwts.builder()
                .subject("missing@vulnerax.io")
                .signWith(key)
                .compact();

        request.addHeader("Authorization", "Bearer " + token);
        when(userRepository.findByEmail("missing@vulnerax.io")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, filterChain);

        assertThat(TenantContext.getOrganizationId()).isNull();
    }

    @Test
    void doFilter_alwaysClearsTenantContext() throws Exception {
        TenantContext.set(UUID.randomUUID(), null, "test@test.com");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(TenantContext.getOrganizationId()).isNull();
    }

    @Test
    void doFilter_emptyBearer_doesNotParse() throws Exception {
        request.addHeader("Authorization", "Bearer ");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(TenantContext.getOrganizationId()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_nonBearerScheme_doesNotParse() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(TenantContext.getOrganizationId()).isNull();
    }
}
