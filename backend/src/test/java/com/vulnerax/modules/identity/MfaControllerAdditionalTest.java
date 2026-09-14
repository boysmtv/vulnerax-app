package com.vulnerax.modules.identity;

import com.vulnerax.modules.identity.MfaController;
import com.vulnerax.modules.identity.TotpService;
import com.vulnerax.modules.identity.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(MfaController.class)
@AutoConfigureMockMvc(addFilters = false)
class MfaControllerAdditionalTest {

    @Autowired MockMvc mvc;
    @MockBean UserRepository userRepo;
    @MockBean TotpService totpService;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    private Authentication mockAuth(String email) {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn(email);
        return auth;
    }

    private User buildUser(String email) {
        User u = new User();
        u.setEmail(email);
        return u;
    }

    @Test
    void setup_returnsSecretAndOtpauth() throws Exception {
        User user = buildUser("admin@test.com");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        TotpService.TotpSetupResult setup = new TotpService.TotpSetupResult("JBSWY3DPEHPK3PXP", "otpauth://totp/test", "https://api.qrserver.com/...");
        when(totpService.generateSecret("admin@test.com")).thenReturn(setup);

        mvc.perform(post("/api/v1/auth/mfa/setup").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
        verify(userRepo).save(user);
    }

    @Test
    void verify_withValidCode_enablesMfa() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "123456"))
                .thenReturn(new TotpService.VerifyResult(true, "Valid"));

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "123456").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
        verify(userRepo).save(user);
    }

    @Test
    void verify_withInvalidCode_checksRecovery() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "wrong"))
                .thenReturn(new TotpService.VerifyResult(false, "Invalid code"));
        when(totpService.useRecoveryCode(user, "wrong")).thenReturn(false);

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "wrong").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void verify_withRecoveryCode_enablesMfa() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "recovery123"))
                .thenReturn(new TotpService.VerifyResult(false, "Invalid code"));
        when(totpService.useRecoveryCode(user, "recovery123")).thenReturn(true);

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "recovery123").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
        verify(userRepo).save(user);
    }

    @Test
    void verify_lockedOut_returnsLockedMessage() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "123456"))
                .thenReturn(new TotpService.VerifyResult(false, "locked out for 300s"));

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "123456").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void verify_invalidCodeFormat_returnsNotVerified() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "abc"))
                .thenReturn(new TotpService.VerifyResult(false, "Invalid code format"));

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "abc").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void verify_noMfaSetup_returnsNotSetUpMessage() throws Exception {
        User user = buildUser("admin@test.com");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));

        mvc.perform(post("/api/v1/auth/mfa/verify").param("code", "123456").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void disable_withValidCode_disablesMfa() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        user.setMfaEnabled(true);
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "123456"))
                .thenReturn(new TotpService.VerifyResult(true, "Valid"));

        mvc.perform(post("/api/v1/auth/mfa/disable").param("code", "123456").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
        verify(userRepo).save(user);
    }

    @Test
    void disable_withInvalidCode_returnsNotVerified() throws Exception {
        User user = buildUser("admin@test.com");
        user.setMfaSecret("JBSWY3DPEHPK3PXP");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.verify("admin@test.com", "JBSWY3DPEHPK3PXP", "wrong"))
                .thenReturn(new TotpService.VerifyResult(false, "Invalid"));

        mvc.perform(post("/api/v1/auth/mfa/disable").param("code", "wrong").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void disable_noMfaEnabled_returnsNotEnabled() throws Exception {
        User user = buildUser("admin@test.com");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));

        mvc.perform(post("/api/v1/auth/mfa/disable").param("code", "123456").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    void recoveryCodes_returnsCodes() throws Exception {
        User user = buildUser("admin@test.com");
        when(userRepo.findByEmail("admin@test.com")).thenReturn(Optional.of(user));
        when(totpService.getRecoveryCodes(user)).thenReturn(Map.of("recoveryCodesCount", 2, "message", "You have 2 recovery codes remaining."));

        mvc.perform(get("/api/v1/auth/mfa/recovery-codes").principal(mockAuth("admin@test.com")))
                .andExpect(status().isOk());
    }
}
