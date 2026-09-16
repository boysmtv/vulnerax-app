package com.vulnerax.modules.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnerax.common.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    MockMvc mvc;
    ObjectMapper om = new ObjectMapper();

    @Mock AuthService authService;
    AuthController controller;

    @BeforeEach
    void setUp() {
        controller = new AuthController(authService);
        var validator = new org.springframework.validation.beanvalidation.LocalValidatorFactoryBean();
        validator.afterPropertiesSet();
        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void login_returns_token() throws Exception {
        when(authService.login(any(), any())).thenReturn(Map.of("token","tok","refreshToken","ref","user", Map.of("email","a@b.com")));
        var body = Map.of("email","a@b.com","password","secret123");
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.token").value("tok"));
    }

    @Test
    void login_validation_fails_when_email_blank() throws Exception {
        var body = Map.of("email","","password","p");
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_creates_user() throws Exception {
        when(authService.register(any(), any(), any(), any())).thenReturn(Map.of("token","tok2"));
        var body = Map.of("email","new@b.com","password","Admin12345!abc","fullName","New User","role","DEVELOPER");
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token").value("tok2"));
    }

    @Test
    void me_returns_user_when_authenticated() throws Exception {
        when(authService.me("me@b.com")).thenReturn(Map.of("email","me@b.com","role","DEVELOPER"));
        var auth = new UsernamePasswordAuthenticationToken("me@b.com", "N/A", java.util.List.of());
        mvc.perform(get("/api/v1/auth/me").principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("me@b.com"));
    }

    @Test
    void auth_endpoints_permitAll_without_token() throws Exception {
        when(authService.login(any(),any())).thenReturn(Map.of("token","x"));
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.com\",\"password\":\"p\"}"))
                .andExpect(status().isOk());
    }
}
