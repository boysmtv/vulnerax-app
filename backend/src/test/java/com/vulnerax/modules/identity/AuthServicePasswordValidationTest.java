package com.vulnerax.modules.identity;

import com.vulnerax.common.exception.BusinessException;
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
class AuthServicePasswordValidationTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder encoder;
    @Mock private JwtTokenProvider jwt;
    @InjectMocks private AuthService authService;

    @Test
    void register_nullPassword_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", null, "User", null));
    }

    @Test
    void register_tooShort_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", "Ab1!", "User", null));
    }

    @Test
    void register_noUppercase_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", "lowercase123!@", "User", null));
    }

    @Test
    void register_noLowercase_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", "UPPERCASE123!@", "User", null));
    }

    @Test
    void register_noDigit_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", "NoDigitHere!@#", "User", null));
    }

    @Test
    void register_noSpecialChar_throws() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        assertThrows(BusinessException.class,
                () -> authService.register("test@test.com", "NoSpecialChar12", "User", null));
    }

    @Test
    void register_validPassword_succeeds() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("$2a$10$hashed");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwt.generateToken(any(), any())).thenReturn("jwt-token");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh-token");

        Map<String, Object> result = authService.register(
                "test@test.com", "ValidPass123!@", "User", "DEVELOPER");

        assertNotNull(result);
        assertEquals("jwt-token", result.get("token"));
    }

    @Test
    void register_withNullRole_defaultsToDeveloper() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("$2a$10$hashed");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwt.generateToken(any(), any())).thenReturn("jwt-token");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh-token");

        Map<String, Object> result = authService.register(
                "test@test.com", "ValidPass123!@", "User", null);

        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) result.get("user");
        assertEquals("DEVELOPER", user.get("role"));
    }

    @Test
    void register_withExplicitRole_usesThatRole() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("$2a$10$hashed");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwt.generateToken(any(), any())).thenReturn("jwt-token");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh-token");

        Map<String, Object> result = authService.register(
                "test@test.com", "ValidPass123!@", "User", "SECURITY_ADMIN");

        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) result.get("user");
        assertEquals("SECURITY_ADMIN", user.get("role"));
    }
}
