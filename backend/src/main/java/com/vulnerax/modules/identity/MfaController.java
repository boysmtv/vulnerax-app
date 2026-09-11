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
        // generate cryptographically secure TOTP secret (Base32, 160-bit) — no hardcoded value
        java.security.SecureRandom sr = new java.security.SecureRandom();
        byte[] bytes = new byte[20];
        sr.nextBytes(bytes);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder sb = new StringBuilder(32);
        int bits = 0, value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(alphabet.charAt((value >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(alphabet.charAt((value << (5 - bits)) & 31));
        String secret = sb.toString();
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
