package com.vulnerax.modules.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TotpServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;
    @InjectMocks TotpService service;

    // generateSecret
    @Test
    void generateSecret_returnsValidSetup() {
        var result = service.generateSecret("user@example.com");
        assertThat(result.secret()).isNotBlank();
        assertThat(result.otpauthUri()).contains("otpauth://totp/VulneraX:user@example.com");
        assertThat(result.otpauthUri()).contains("secret=" + result.secret());
        assertThat(result.otpauthUri()).contains("issuer=VulneraX");
        assertThat(result.qrUrl()).contains("api.qrserver.com");
    }

    @Test
    void generateSecret_secretIsBase32() {
        var result = service.generateSecret("test@test.com");
        assertThat(result.secret()).matches("[A-Z2-7]+");
    }

    @Test
    void generateSecret_differentCallsProduceDifferentSecrets() {
        var r1 = service.generateSecret("a@b.com");
        var r2 = service.generateSecret("a@b.com");
        assertThat(r1.secret()).isNotEqualTo(r2.secret());
    }

    // verify
    @Test
    void verify_invalidCodeFormat_returnsFalse() {
        var result = service.verify("user@example.com", "JBSWY3DPEHPK3PXP", "abc");
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("Invalid code format");
    }

    @Test
    void verify_nullCode_returnsFalse() {
        var result = service.verify("user@example.com", "JBSWY3DPEHPK3PXP", null);
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("Invalid code format");
    }

    @Test
    void verify_nullSecret_returnsFalse() {
        var result = service.verify("user@example.com", null, "123456");
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("Invalid code format");
    }

    @Test
    void verify_codeTooShort_returnsFalse() {
        var result = service.verify("user@example.com", "JBSWY3DPEHPK3PXP", "12345");
        assertThat(result.success()).isFalse();
    }

    @Test
    void verify_codeTooLong_returnsFalse() {
        var result = service.verify("user@example.com", "JBSWY3DPEHPK3PXP", "1234567");
        assertThat(result.success()).isFalse();
    }

    @Test
    void verify_validCodeMatches_returnsTrue() {
        String secret = "JBSWY3DPEHPK3PXP";
        long timeStep = System.currentTimeMillis() / 1000 / 30;
        String code = generateTotpCode(secret, timeStep);
        var result = service.verify("user@example.com", secret, code);
        assertThat(result.success()).isTrue();
        assertThat(result.message()).contains("TOTP verified");
    }

    @Test
    void verify_invalidCode_returnsFalse() {
        String secret = "JBSWY3DPEHPK3PXP";
        var result = service.verify("user@example.com", secret, "000000");
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("Invalid TOTP code");
    }

    @Test
    void verify_multipleFailedAttempts_showsRemainingCount() {
        String secret = "JBSWY3DPEHPK3PXP";
        service.verify("user@example.com", secret, "000000");
        service.verify("user@example.com", secret, "000000");
        var result = service.verify("user@example.com", secret, "000000");
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("attempts remaining");
    }

    @Test
    void verify_lockoutAfterMaxAttempts() {
        String secret = "JBSWY3DPEHPK3PXP";
        for (int i = 0; i < 5; i++) {
            service.verify("user@example.com", secret, "000000");
        }
        var result = service.verify("user@example.com", secret, "000000");
        assertThat(result.success()).isFalse();
        assertThat(result.message()).contains("locked");
    }

    // generateRecoveryCodes
    @Test
    void generateRecoveryCodes_returnsCorrectCount() {
        List<String> codes = service.generateRecoveryCodes(10);
        assertThat(codes).hasSize(10);
    }

    @Test
    void generateRecoveryCodes_eachCodeMatchesFormat() {
        List<String> codes = service.generateRecoveryCodes(5);
        for (String code : codes) {
            assertThat(code).matches("\\d{4}-\\d{4}");
        }
    }

    @Test
    void generateRecoveryCodes_differentCallsProduceDifferentCodes() {
        List<String> codes1 = service.generateRecoveryCodes(5);
        List<String> codes2 = service.generateRecoveryCodes(5);
        assertThat(codes1).isNotEqualTo(codes2);
    }

    @Test
    void generateRecoveryCodes_zeroCount_returnsEmptyList() {
        List<String> codes = service.generateRecoveryCodes(0);
        assertThat(codes).isEmpty();
    }

    // getRecoveryCodes
    @Test
    void getRecoveryCodes_noExistingCodes_generatesAndSaves() {
        User user = User.builder().email("user@test.com").recoveryCodes(null).build();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");
        Map<String, Object> result = service.getRecoveryCodes(user);
        assertThat(result).containsKey("recoveryCodes");
        assertThat(result).containsKey("message");
        @SuppressWarnings("unchecked")
        List<String> recoveryCodes = (List<String>) result.get("recoveryCodes");
        assertThat(recoveryCodes).hasSize(10);
        verify(userRepository).save(user);
    }

    @Test
    void getRecoveryCodes_emptyExistingCodes_generatesAndSaves() {
        User user = User.builder().email("user@test.com").recoveryCodes(new ArrayList<>()).build();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");
        Map<String, Object> result = service.getRecoveryCodes(user);
        assertThat(result).containsKey("recoveryCodes");
        verify(userRepository).save(user);
    }

    @Test
    void getRecoveryCodes_existingCodes_returnsCount() {
        User user = User.builder().email("user@test.com")
                .recoveryCodes(List.of("h1", "h2", "h3")).build();
        Map<String, Object> result = service.getRecoveryCodes(user);
        assertThat(result).containsKey("recoveryCodesCount");
        assertThat(result.get("recoveryCodesCount")).isEqualTo(3);
        verify(userRepository, never()).save(any());
    }

    // useRecoveryCode
    @Test
    void useRecoveryCode_validCode_removesAndSaves() {
        User user = User.builder().email("user@test.com")
                .recoveryCodes(new ArrayList<>(List.of("hashed1", "hashed2"))).build();
        when(passwordEncoder.matches("1234-5678", "hashed1")).thenReturn(true);
        boolean result = service.useRecoveryCode(user, "1234-5678");
        assertThat(result).isTrue();
        assertThat(user.getRecoveryCodes()).hasSize(1);
        verify(userRepository).save(user);
    }

    @Test
    void useRecoveryCode_codeNotFound_returnsFalse() {
        User user = User.builder().email("user@test.com")
                .recoveryCodes(new ArrayList<>(List.of("hashed1"))).build();
        when(passwordEncoder.matches("wrong", "hashed1")).thenReturn(false);
        boolean result = service.useRecoveryCode(user, "wrong");
        assertThat(result).isFalse();
        verify(userRepository, never()).save(any());
    }

    @Test
    void useRecoveryCode_nullRecoveryCodes_returnsFalse() {
        User user = User.builder().email("user@test.com").recoveryCodes(null).build();
        boolean result = service.useRecoveryCode(user, "1234-5678");
        assertThat(result).isFalse();
    }

    @Test
    void useRecoveryCode_secondCodeWorks_afterFirstUsed() {
        User user = User.builder().email("user@test.com")
                .recoveryCodes(new ArrayList<>(List.of("hashed1", "hashed2"))).build();
        when(passwordEncoder.matches("2222-2222", "hashed1")).thenReturn(false);
        when(passwordEncoder.matches("2222-2222", "hashed2")).thenReturn(true);
        boolean result = service.useRecoveryCode(user, "2222-2222");
        assertThat(result).isTrue();
        assertThat(user.getRecoveryCodes()).hasSize(1);
        verify(userRepository).save(user);
    }

    // Helper to generate valid TOTP code for testing
    private String generateTotpCode(String secret, long timeStep) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            byte[] key = decodeBase32(secret);
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(8);
            buffer.putLong(timeStep);
            byte[] hash = mac.doFinal(buffer.array());
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);
            int otp = binary % (int) Math.pow(10, 6);
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] decodeBase32(String secret) {
        String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String cleaned = secret.replace("=", "").toUpperCase();
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(cleaned.length() * 5 / 8);
        int bits = 0, value = 0;
        for (char c : cleaned.toCharArray()) {
            int idx = BASE32_CHARS.indexOf(c);
            if (idx < 0) continue;
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                buffer.put((byte) (value >> (bits - 8)));
                bits -= 8;
            }
        }
        return java.util.Arrays.copyOf(buffer.array(), buffer.position());
    }
}
