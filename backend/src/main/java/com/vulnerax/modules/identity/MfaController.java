package com.vulnerax.modules.identity;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/mfa")
@RequiredArgsConstructor
public class MfaController {
    private final UserRepository userRepo;

    @PostMapping("/setup")
    public ApiResponse<?> setup(Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();
        String secret = "JBSWY3DPEHPK3PXP-" + UUID.randomUUID().toString().substring(0,8);
        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        userRepo.save(user);
        String otpauth = "otpauth://totp/VulneraX:" + user.getEmail() + "?secret=" + secret + "&issuer=VulneraX";
        return ApiResponse.ok(Map.of("secret", secret, "otpauth", otpauth, "qr", "https://api.qrserver.com/v1/create-qr-code/?data=" + otpauth));
    }

    @PostMapping("/verify")
    public ApiResponse<?> verify(@RequestParam String code, Authentication auth) {
        // mock verification: accept 123456 or any 6 digits for demo
        boolean ok = code != null && code.matches("\\d{6}");
        return ApiResponse.ok(Map.of("verified", ok, "message", ok ? "MFA verified" : "Invalid code (demo accepts any 6 digits)"));
    }

    @PostMapping("/disable")
    public ApiResponse<?> disable(Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        userRepo.save(user);
        return ApiResponse.ok(Map.of("mfaEnabled", false));
    }
}
