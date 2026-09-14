package com.vulnerax.modules.identity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock JwtTokenProvider tokenProvider;
    @Mock UserRepository userRepository;
    @Mock FilterChain filterChain;
    @InjectMocks JwtAuthFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilter_validToken_setsAuthentication() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer valid-token");
        when(tokenProvider.validateToken("valid-token")).thenReturn(true);
        when(tokenProvider.getEmailFromToken("valid-token")).thenReturn("admin@vulnerax.io");
        User user = User.builder().email("admin@vulnerax.io").role(User.Role.ORG_OWNER).build();
        when(userRepository.findByEmail("admin@vulnerax.io")).thenReturn(Optional.of(user));

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo("admin@vulnerax.io");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_invalidToken_doesNotSetAuth() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer invalid-token");
        when(tokenProvider.validateToken("invalid-token")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_noAuthHeader_doesNotSetAuth() throws ServletException, IOException {
        filter.doFilterInternal(request, response, filterChain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_emptyBearer_doesNotSetAuth() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer ");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_bearerWithoutPrefix_doesNotExtract() throws ServletException, IOException {
        request.addHeader("Authorization", "some-token-without-bearer");
        filter.doFilterInternal(request, response, filterChain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_validToken_userNotFound_doesNotSetAuth() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer valid-token");
        when(tokenProvider.validateToken("valid-token")).thenReturn(true);
        when(tokenProvider.getEmailFromToken("valid-token")).thenReturn("missing@vulnerax.io");
        when(userRepository.findByEmail("missing@vulnerax.io")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilter_userWithDifferentRole_setsCorrectAuthority() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer dev-token");
        when(tokenProvider.validateToken("dev-token")).thenReturn(true);
        when(tokenProvider.getEmailFromToken("dev-token")).thenReturn("dev@vulnerax.io");
        User user = User.builder().email("dev@vulnerax.io").role(User.Role.DEVELOPER).build();
        when(userRepository.findByEmail("dev@vulnerax.io")).thenReturn(Optional.of(user));

        filter.doFilterInternal(request, response, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth.getAuthorities()).hasSize(1);
        assertThat(auth.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_DEVELOPER");
    }

    @Test
    void doFilter_alwaysCallsChain() throws ServletException, IOException {
        filter.doFilterInternal(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }
}
