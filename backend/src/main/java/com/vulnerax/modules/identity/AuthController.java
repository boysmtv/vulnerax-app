package com.vulnerax.modules.identity;

import com.vulnerax.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ApiResponse<?> register(@Valid @RequestBody RegisterReq req) {
        return ApiResponse.ok(authService.register(req.getEmail(), req.getPassword(), req.getFullName(), req.getRole()));
    }

    @PostMapping("/login")
    public ApiResponse<?> login(@Valid @RequestBody LoginReq req) {
        return ApiResponse.ok(authService.login(req.getEmail(), req.getPassword()));
    }

    @GetMapping("/me")
    public ApiResponse<?> me(Authentication auth) {
        return ApiResponse.ok(authService.me(auth.getName()));
    }

    @Data
    public static class RegisterReq {
        @Email @NotBlank private String email;
        @NotBlank private String password;
        @NotBlank private String fullName;
        private String role;
    }

    @Data
    public static class LoginReq {
        @Email @NotBlank private String email;
        @NotBlank private String password;
    }
}
