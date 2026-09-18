package com.vulnerax.modules.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaControllerUnitTest {

    @Mock UserRepository userRepo;
    @Mock TotpService totpService;
    @InjectMocks MfaController controller;

    private User user;
    private Authentication auth;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setEmail("a@x.io");
        auth = mock(Authentication.class);
        lenient().when(auth.getName()).thenReturn("a@x.io");
        lenient().when(userRepo.findByEmail("a@x.io")).thenReturn(Optional.of(user));
    }

    @Test
    void setup_generatesAndSaves() {
        when(totpService.generateSecret("a@x.io"))
                .thenReturn(new TotpService.TotpSetupResult("S", "otpauth://x", "http://qr"));
        var res = controller.setup(auth);
        assertThat(res.isSuccess()).isTrue();
        assertThat(user.getMfaSecret()).isEqualTo("S");
        verify(userRepo).save(user);
    }

    @Test
    void verify_totpSuccess_enables() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "123456"))
                .thenReturn(new TotpService.VerifyResult(true, "OK"));
        var res = controller.verify("123456", auth);
        assertThat(res.isSuccess()).isTrue();
        assertThat(user.getMfaEnabled()).isTrue();
    }

    @Test
    void verify_recoveryCode_enables() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "RCODE"))
                .thenReturn(new TotpService.VerifyResult(false, "Wrong code"));
        when(totpService.useRecoveryCode(user, "RCODE")).thenReturn(true);
        var res = controller.verify("RCODE", auth);
        assertThat(res.isSuccess()).isTrue();
        assertThat(((Map<?, ?>) res.getData()).get("method")).isEqualTo("RECOVERY");
    }

    @Test
    void verify_wrongCode_noRecovery() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "000000"))
                .thenReturn(new TotpService.VerifyResult(false, "Wrong code"));
        when(totpService.useRecoveryCode(user, "000000")).thenReturn(false);
        var res = controller.verify("000000", auth);
        assertThat(((Map<?, ?>) res.getData()).get("verified")).isEqualTo(false);
    }

    @Test
    void verify_invalidFormat_skipsRecovery() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "abc"))
                .thenReturn(new TotpService.VerifyResult(false, "Invalid code format"));
        var res = controller.verify("abc", auth);
        assertThat(((Map<?, ?>) res.getData()).get("verified")).isEqualTo(false);
        verify(totpService, never()).useRecoveryCode(any(), any());
    }

    @Test
    void verify_locked_skipsRecovery() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "123456"))
                .thenReturn(new TotpService.VerifyResult(false, "Account locked for 5 min"));
        var res = controller.verify("123456", auth);
        assertThat(((Map<?, ?>) res.getData()).get("verified")).isEqualTo(false);
        verify(totpService, never()).useRecoveryCode(any(), any());
    }

    @Test
    void verify_noSecret_setupFirst() {
        user.setMfaSecret(null);
        var res = controller.verify("123456", auth);
        assertThat(((Map<?, ?>) res.getData()).get("message").toString()).contains("setup first");
    }

    @Test
    void disable_success() {
        user.setMfaSecret("S");
        user.setMfaEnabled(true);
        when(totpService.verify("a@x.io", "S", "123456"))
                .thenReturn(new TotpService.VerifyResult(true, "OK"));
        var res = controller.disable("123456", auth);
        assertThat(res.isSuccess()).isTrue();
        assertThat(user.getMfaEnabled()).isFalse();
        assertThat(user.getMfaSecret()).isNull();
    }

    @Test
    void disable_wrongCode() {
        user.setMfaSecret("S");
        when(totpService.verify("a@x.io", "S", "000000"))
                .thenReturn(new TotpService.VerifyResult(false, "Wrong code"));
        var res = controller.disable("000000", auth);
        assertThat(((Map<?, ?>) res.getData()).get("verified")).isEqualTo(false);
    }

    @Test
    void disable_noSecret() {
        user.setMfaSecret(null);
        var res = controller.disable("123456", auth);
        assertThat(((Map<?, ?>) res.getData()).get("message").toString()).contains("not enabled");
    }

    @Test
    void recoveryCodes_delegates() {
        when(totpService.getRecoveryCodes(user)).thenReturn(Map.of("codes", List.of("a", "b")));
        var res = controller.getRecoveryCodes(auth);
        assertThat(res.isSuccess()).isTrue();
    }
}
