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

        if (user.getMfaSecret() != null && totpService.verify(user.getMfaSecret(), code)) {
            user.setMfaEnabled(true);
            userRepo.save(user);
            return ApiResponse.ok(Map.of(
                    "verified", true,
                    "message", "MFA enabled successfully",
                    "method", "TOTP"
            ));
        }

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
                "message", "Invalid TOTP code or recovery code"
        ));
    }

    @PostMapping("/disable")
    public ApiResponse<?> disable(@RequestParam String code, Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();

        if (user.getMfaSecret() != null && totpService.verify(user.getMfaSecret(), code)) {
            user.setMfaEnabled(false);
            user.setMfaSecret(null);
            user.setRecoveryCodes(null);
            userRepo.save(user);
            return ApiResponse.ok(Map.of("mfaEnabled", false, "message", "MFA disabled"));
        }

        return ApiResponse.ok(Map.of("verified", false, "message", "Invalid code"));
    }

    @GetMapping("/recovery-codes")
    public ApiResponse<?> getRecoveryCodes(Authentication auth) {
        var user = userRepo.findByEmail(auth.getName()).orElseThrow();
        return ApiResponse.ok(totpService.getRecoveryCodes(user));
    }
}
