package com.vulnerax.modules.identity;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth/mfa")
@RequiredArgsConstructor
public class MfaController {
    private final UserRepository userRepo;
    private final TotpService totpService;

    @PostMapping("/setup")
    public ApiResponse<?> setup(Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();
        var setup = totpService.generateSecret(user.getEmail());
        user.setMfaSecret(setup.secret());
        userRepo.save(user);
        return ApiResponse.ok(Map.of(
                "secret", setup.secret(),
                "otpauth", setup.otpauthUri(),
                "qr", setup.qrUrl(),
                "message", "Scan QR code with your authenticator app, then verify with /verify endpoint"
        ));
    }

    @PostMapping("/verify")
    public ApiResponse<?> verify(@RequestParam String code, Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();

        // TOTP verification with rate limiting
        if (user.getMfaSecret() != null) {
            var result = totpService.verify(user.getEmail(), user.getMfaSecret(), code);
            if (result.success()) {
                user.setMfaEnabled(true);
                userRepo.save(user);
                return ApiResponse.ok(Map.of(
                        "verified", true,
                        "message", result.message(),
                        "method", "TOTP"
                ));
            }
            // If not locked out, check recovery codes
            if (!"Invalid code format".equals(result.message()) && !result.message().contains("locked")) {
                if (totpService.useRecoveryCode(user, code)) {
                    user.setMfaEnabled(true);
                    userRepo.save(user);
                    return ApiResponse.ok(Map.of(
                            "verified", true,
                            "message", "MFA enabled via recovery code",
                            "method", "RECOVERY"
                    ));
                }
                return ApiResponse.ok(Map.of(
                        "verified", false,
                        "message", result.message()
                ));
            }
            return ApiResponse.ok(Map.of(
                    "verified", false,
                    "message", result.message()
            ));
        }

        return ApiResponse.ok(Map.of(
                "verified", false,
                "message", "MFA not set up. Call /setup first."
        ));
    }

    @PostMapping("/disable")
    public ApiResponse<?> disable(@RequestParam String code, Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();

        if (user.getMfaSecret() != null) {
            var result = totpService.verify(user.getEmail(), user.getMfaSecret(), code);
            if (result.success()) {
                user.setMfaEnabled(false);
                user.setMfaSecret(null);
                user.setRecoveryCodes(null);
                userRepo.save(user);
                return ApiResponse.ok(Map.of("mfaEnabled", false, "message", "MFA disabled"));
            }
            return ApiResponse.ok(Map.of("verified", false, "message", result.message()));
        }

        return ApiResponse.ok(Map.of("verified", false, "message", "MFA not enabled"));
    }

    @GetMapping("/recovery-codes")
    public ApiResponse<?> getRecoveryCodes(Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();
        return ApiResponse.ok(totpService.getRecoveryCodes(user));
    }
}
