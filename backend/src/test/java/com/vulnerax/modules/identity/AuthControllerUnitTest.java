package com.vulnerax.modules.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerUnitTest {

    @Mock AuthService authService;
    @InjectMocks AuthController controller;

    @Test
    void register_delegates() {
        AuthController.RegisterReq req = new AuthController.RegisterReq();
        req.setEmail("a@x.io"); req.setPassword("Secret123!x"); req.setFullName("Alice"); req.setRole("DEVELOPER");
        when(authService.register("a@x.io", "Secret123!x", "Alice", "DEVELOPER"))
                .thenReturn(Map.of("id", "1"));
        var res = controller.register(req);
        assertThat(res.isSuccess()).isTrue();
        assertThat(res.getData()).isEqualTo(Map.of("id", "1"));
    }

    @Test
    void login_delegates() {
        AuthController.LoginReq req = new AuthController.LoginReq();
        req.setEmail("a@x.io"); req.setPassword("pw");
        when(authService.login("a@x.io", "pw")).thenReturn(Map.of("token", "t"));
        var res = controller.login(req);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void me_usesAuthName() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("a@x.io");
        when(authService.me("a@x.io")).thenReturn(Map.of("email", "a@x.io"));
        var res = controller.me(auth);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void registerReq_dto() {
        AuthController.RegisterReq r = new AuthController.RegisterReq();
        r.setEmail("e"); r.setPassword("p"); r.setFullName("n"); r.setRole("R");
        assertThat(r.getEmail()).isEqualTo("e");
        assertThat(r.toString()).contains("e");
        AuthController.RegisterReq r2 = new AuthController.RegisterReq();
        r2.setEmail("e"); r2.setPassword("p"); r2.setFullName("n"); r2.setRole("R");
        assertThat(r).isEqualTo(r2);
        assertThat(r.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void loginReq_dto() {
        AuthController.LoginReq l = new AuthController.LoginReq();
        l.setEmail("e"); l.setPassword("p");
        assertThat(l.getPassword()).isEqualTo("p");
        assertThat(l.toString()).contains("e");
        AuthController.LoginReq l2 = new AuthController.LoginReq();
        l2.setEmail("e"); l2.setPassword("p");
        assertThat(l).isEqualTo(l2);
        assertThat(l.hashCode()).isEqualTo(l2.hashCode());
        assertThat(l).isNotEqualTo(null);
        assertThat(l).isNotEqualTo("x");
        l2.setPassword("other");
        assertThat(l).isNotEqualTo(l2);
    }

    @Test
    void registerReq_notEqual_variants() {
        AuthController.RegisterReq r = new AuthController.RegisterReq();
        r.setEmail("e"); r.setPassword("p"); r.setFullName("n");
        assertThat(r).isNotEqualTo(null);
        assertThat(r).isNotEqualTo("x");
        AuthController.RegisterReq r2 = new AuthController.RegisterReq();
        r2.setEmail("other"); r2.setPassword("p"); r2.setFullName("n");
        assertThat(r).isNotEqualTo(r2);
    }
}
