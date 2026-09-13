package com.vulnerax.modules.identity;

import com.vulnerax.common.exception.BusinessException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private AuthService authService;

    private JwtTokenProvider createProvider() {
        return new JwtTokenProvider(
                "vulnerax-super-secret-jwt-key-must-be-at-least-64-chars-long-for-hs512-change-me",
                86400000,
                604800000
        );
    }

    @Test
    void generateToken_validEmail_returnsToken() {
        JwtTokenProvider provider = createProvider();

        String token = provider.generateToken("test@vulnerax.com", "DEVELOPER");

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void getEmailFromToken_validToken_returnsEmail() {
        JwtTokenProvider provider = createProvider();
        String token = provider.generateToken("test@vulnerax.com", "DEVELOPER");

        String email = provider.getEmailFromToken(token);

        assertEquals("test@vulnerax.com", email);
    }

    @Test
    void validateToken_validToken_returnsTrue() {
        JwtTokenProvider provider = createProvider();
        String token = provider.generateToken("test@vulnerax.com", "DEVELOPER");

        assertTrue(provider.validateToken(token));
    }

    @Test
    void validateToken_tamperedToken_returnsFalse() {
        JwtTokenProvider provider = createProvider();
        String token = provider.generateToken("test@vulnerax.com", "DEVELOPER");

        assertFalse(provider.validateToken(token + "tampered"));
    }

    @Test
    void validateToken_emptyToken_returnsFalse() {
        JwtTokenProvider provider = createProvider();

        assertFalse(provider.validateToken(""));
    }

    @Test
    void generateRefreshToken_returnsToken() {
        JwtTokenProvider provider = createProvider();

        String refreshToken = provider.generateRefreshToken("test@vulnerax.com");

        assertNotNull(refreshToken);
        assertTrue(provider.validateToken(refreshToken));
    }
}
