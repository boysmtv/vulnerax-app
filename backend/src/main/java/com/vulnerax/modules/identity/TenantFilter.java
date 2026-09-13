package com.vulnerax.modules.identity;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TenantFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;

    public TenantFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    io.jsonwebtoken.Claims claims = io.jsonwebtoken.Jwts.parser()
                            .verifyWith(getKey())
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();
                    String email = claims.getSubject();
                    if (email != null) {
                        var user = userRepository.findByEmail(email).orElse(null);
                        if (user != null) {
                            TenantContext.set(user.getOrganizationId(), null, user.getEmail());
                        }
                    }
                } catch (Exception ignored) {}
            }
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private javax.crypto.SecretKey getKey() {
        String secret = System.getenv().getOrDefault("JWT_SECRET",
                "vulnerax-super-secret-jwt-key-must-be-at-least-64-chars-long-for-hs512-change-me");
        return io.jsonwebtoken.security.Keys.hmacShaKeyFor(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
