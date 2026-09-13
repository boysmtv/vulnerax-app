package com.vulnerax.modules.identity;

import com.vulnerax.common.exception.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private JwtTokenProvider jwt;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .email("test@vulnerax.com")
                .passwordHash("$2a$10$hashed")
                .fullName("Test User")
                .role(User.Role.DEVELOPER)
                .active(true)
                .build();
        testUser.setId(java.util.UUID.randomUUID());
    }

    @Test
    void register_success() {
        when(userRepository.existsByEmail("test@vulnerax.com")).thenReturn(false);
        when(encoder.encode("password123")).thenReturn("$2a$10$hashed");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwt.generateToken(any(), any())).thenReturn("jwt-token");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh-token");

        Map<String, Object> result = authService.register("test@vulnerax.com", "password123", "Test User", "DEVELOPER");

        assertNotNull(result);
        assertEquals("jwt-token", result.get("token"));
        assertEquals("refresh-token", result.get("refreshToken"));
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_duplicateEmail_throws() {
        when(userRepository.existsByEmail("test@vulnerax.com")).thenReturn(true);

        assertThrows(BusinessException.class,
                () -> authService.register("test@vulnerax.com", "password123", "Test User", null));
    }

    @Test
    void login_success() {
        when(userRepository.findByEmail("test@vulnerax.com")).thenReturn(Optional.of(testUser));
        when(encoder.matches("password123", testUser.getPasswordHash())).thenReturn(true);
        when(jwt.generateToken(any(), any())).thenReturn("jwt-token");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh-token");

        Map<String, Object> result = authService.login("test@vulnerax.com", "password123");

        assertNotNull(result);
        assertEquals("jwt-token", result.get("token"));
    }

    @Test
    void login_wrongPassword_throws() {
        when(userRepository.findByEmail("test@vulnerax.com")).thenReturn(Optional.of(testUser));
        when(encoder.matches("wrong", testUser.getPasswordHash())).thenReturn(false);

        assertThrows(BusinessException.class,
                () -> authService.login("test@vulnerax.com", "wrong"));
    }

    @Test
    void login_userNotFound_throws() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        assertThrows(BusinessException.class,
                () -> authService.login("unknown@test.com", "password"));
    }

    @Test
    void me_success() {
        when(userRepository.findByEmail("test@vulnerax.com")).thenReturn(Optional.of(testUser));

        Map<String, Object> result = authService.me("test@vulnerax.com");

        assertNotNull(result);
        assertEquals("test@vulnerax.com", result.get("email"));
        assertEquals("DEVELOPER", result.get("role"));
    }

    @Test
    void me_userNotFound_throws() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        assertThrows(BusinessException.class,
                () -> authService.me("unknown@test.com"));
    }
}
