package com.vulnerax.modules.identity;

import com.vulnerax.common.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwt;

    @Transactional
    public Map<String, Object> register(String email, String password, String fullName, String role) {
        if (userRepository.existsByEmail(email)) throw new BusinessException("Email already exists");
        User u = User.builder()
                .email(email)
                .passwordHash(encoder.encode(password))
                .fullName(fullName)
                .role(role != null ? User.Role.valueOf(role) : User.Role.DEVELOPER)
                .build();
        userRepository.save(u);
        String token = jwt.generateToken(u.getEmail(), u.getRole().name());
        String refresh = jwt.generateRefreshToken(u.getEmail());
        return Map.of("token", token, "refreshToken", refresh, "user", Map.of("id", u.getId(), "email", u.getEmail(), "role", u.getRole().name(), "fullName", u.getFullName()));
    }

    public Map<String, Object> login(String email, String password) {
        User u = userRepository.findByEmail(email).orElseThrow(() -> new BusinessException("Invalid credentials"));
        if (!encoder.matches(password, u.getPasswordHash())) throw new BusinessException("Invalid credentials");
        String token = jwt.generateToken(u.getEmail(), u.getRole().name());
        String refresh = jwt.generateRefreshToken(u.getEmail());
        return Map.of("token", token, "refreshToken", refresh, "user", Map.of("id", u.getId(), "email", u.getEmail(), "role", u.getRole().name(), "fullName", u.getFullName()));
    }

    public Map<String, Object> me(String email) {
        User u = userRepository.findByEmail(email).orElseThrow(() -> new BusinessException("User not found"));
        return Map.of("id", u.getId(), "email", u.getEmail(), "role", u.getRole().name(), "fullName", u.getFullName(), "active", u.getActive());
    }
}
