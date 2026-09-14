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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Optional;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterAdditionalTest {

    @Mock JwtTokenProvider tokenProvider;
    @Mock UserRepository userRepository;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain filterChain;

    @InjectMocks JwtAuthFilter filter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_noAuthHeader_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn(null);
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        verify(tokenProvider, never()).validateToken(any());
    }

    @Test
    void doFilterInternal_emptyAuthHeader_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_bearerWithoutToken_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Bearer ");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_bearerWithToken_invalidToken_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Bearer invalid-token");
        when(tokenProvider.validateToken("invalid-token")).thenReturn(false);
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        assertThat_contextIsEmpty();
    }

    @Test
    void doFilterInternal_validToken_userNotFound_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(tokenProvider.validateToken("valid-token")).thenReturn(true);
        when(tokenProvider.getEmailFromToken("valid-token")).thenReturn("user@test.com");
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.empty());
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        assertThat_contextIsEmpty();
    }

    @Test
    void doFilterInternal_validToken_userFound_setsAuthentication() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(tokenProvider.validateToken("valid-token")).thenReturn(true);
        when(tokenProvider.getEmailFromToken("valid-token")).thenReturn("admin@test.com");
        User user = User.builder().email("admin@test.com").role(User.Role.SECURITY_ADMIN).build();
        when(userRepository.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        var auth = SecurityContextHolder.getContext().getAuthentication();
        assert auth != null;
        assert auth.getName().equals("admin@test.com");
    }

    @Test
    void doFilterInternal_nonBearerHeader_callsChain() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Basic abc123");
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
        verify(tokenProvider, never()).validateToken(any());
    }

    private void assertThat_contextIsEmpty() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        assert auth == null;
    }
}
