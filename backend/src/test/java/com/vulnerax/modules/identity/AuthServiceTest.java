package com.vulnerax.modules.identity;

import com.vulnerax.common.exception.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder encoder;
    @Mock JwtTokenProvider jwt;

    AuthService service;

    @BeforeEach
    void setUp() { service = new AuthService(userRepository, encoder, jwt); }

    // login — success flow
    @Test
    void login_success() {
        User u = User.builder().email("a@b.com").passwordHash("hash").fullName("A").role(User.Role.DEVELOPER).build();
        u.setId(UUID.randomUUID());
        when(userRepository.findByEmail("a@b.com")).thenReturn(Optional.of(u));
        when(encoder.matches("pass", "hash")).thenReturn(true);
        when(jwt.generateToken(any(), any())).thenReturn("tok");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh");

        var res = service.login("a@b.com", "pass");
        assertThat(res).containsKeys("token","refreshToken","user");
        assertThat(res.get("token")).isEqualTo("tok");
    }

    @Test
    void login_invalid_password_throws() {
        User u = User.builder().email("a@b.com").passwordHash("hash").fullName("A").build();
        when(userRepository.findByEmail(any())).thenReturn(Optional.of(u));
        when(encoder.matches(any(), any())).thenReturn(false);
        assertThatThrownBy(() -> service.login("a@b.com","wrong")).isInstanceOf(BusinessException.class);
    }

    @Test
    void login_user_not_found_throws() {
        when(userRepository.findByEmail(any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.login("x@y.com","p")).isInstanceOf(BusinessException.class);
    }

    // create / register — success
    @Test
    void register_success() {
        when(userRepository.existsByEmail("new@b.com")).thenReturn(false);
        when(encoder.encode("pass")).thenReturn("hash");
        when(jwt.generateToken(any(), any())).thenReturn("tok");
        when(jwt.generateRefreshToken(any())).thenReturn("refresh");
        // mock save to set id
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });
        var res = service.register("new@b.com","pass","New User","DEVELOPER");
        assertThat(res).containsKey("token");
        verify(userRepository).save(any());
    }

    @Test
    void register_duplicate_throws() {
        when(userRepository.existsByEmail("dup@b.com")).thenReturn(true);
        assertThatThrownBy(() -> service.register("dup@b.com","p","N",null)).isInstanceOf(BusinessException.class);
    }

    // me
    @Test
    void me_success() {
        User u = User.builder().email("me@b.com").fullName("Me").role(User.Role.AUDITOR).build();
        u.setId(UUID.randomUUID());
        when(userRepository.findByEmail("me@b.com")).thenReturn(Optional.of(u));
        var res = service.me("me@b.com");
        assertThat(res.get("email")).isEqualTo("me@b.com");
        assertThat(res.get("role")).isEqualTo("AUDITOR");
    }

    // return / logout implicit — list roles edge
    @Test
    void register_defaults_to_developer_when_role_null() {
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(encoder.encode(any())).thenReturn("h");
        when(jwt.generateToken(any(), eq("DEVELOPER"))).thenReturn("tok");
        when(jwt.generateRefreshToken(any())).thenReturn("r");
        when(userRepository.save(any())).thenAnswer(i -> { User u=i.getArgument(0); u.setId(UUID.randomUUID()); return u; });
        service.register("d@e.com","p","F",null);
        verify(jwt).generateToken(any(), eq("DEVELOPER"));
    }
}
