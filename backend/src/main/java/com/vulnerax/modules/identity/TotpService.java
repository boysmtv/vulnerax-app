package com.vulnerax.modules.identity;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

@Service
public class TotpService {

    private static final int TOTP_DIGITS = 6;
    private static final int TOTP_PERIOD_SECONDS = 30;
    private static final int TOTP_WINDOW = 1; // Allow ±1 window (30s before/after)
    private static final String HMAC_ALGO = "HmacSHA1";
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public TotpService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public TotpSetupResult generateSecret(String email) {
        byte[] buffer = new byte[20];
        new SecureRandom().nextBytes(buffer);

        String secret = encodeBase32(buffer);
        String otpauthUri = String.format(
                "otpauth://totp/VulneraX:%s?secret=%s&issuer=VulneraX&algorithm=SHA1&digits=%d&period=%d",
                email, secret, TOTP_DIGITS, TOTP_PERIOD_SECONDS);

        String qrUrl = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" +
                java.net.URLEncoder.encode(otpauthUri, java.nio.charset.StandardCharsets.UTF_8);

        return new TotpSetupResult(secret, otpauthUri, qrUrl);
    }

    public boolean verify(String secret, String code) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }

        long time = System.currentTimeMillis() / 1000;
        long currentWindow = time / TOTP_PERIOD_SECONDS;

        for (int i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
            String expected = generateOtp(secret, currentWindow + i);
            if (expected.equals(code)) {
                return true;
            }
        }
        return false;
    }

    public List<String> generateRecoveryCodes(int count) {
        List<String> codes = new ArrayList<>();
        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < count; i++) {
            String code = String.format("%04d-%04d", sr.nextInt(10000), sr.nextInt(10000));
            codes.add(code);
        }
        return codes;
    }

    public Map<String, Object> getRecoveryCodes(User user) {
        if (user.getRecoveryCodes() == null || user.getRecoveryCodes().isEmpty()) {
            List<String> codes = generateRecoveryCodes(10);
            List<String> hashed = codes.stream()
                    .map(passwordEncoder::encode)
                    .toList();
            user.setRecoveryCodes(new ArrayList<>(hashed));
            userRepository.save(user);
            return Map.of("recoveryCodes", codes, "message", "Save these codes securely. Each code can only be used once.");
        }
        // Return unhashed display (masked)
        return Map.of("recoveryCodesCount", user.getRecoveryCodes().size(),
                "message", "You have " + user.getRecoveryCodes().size() + " recovery codes remaining.");
    }

    public boolean useRecoveryCode(User user, String code) {
        if (user.getRecoveryCodes() == null) return false;
        List<String> codes = new ArrayList<>(user.getRecoveryCodes());
        for (int i = 0; i < codes.size(); i++) {
            if (passwordEncoder.matches(code, codes.get(i))) {
                codes.remove(i);
                user.setRecoveryCodes(codes);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }

    private String generateOtp(String secret, long timeStep) {
        try {
            byte[] key = decodeBase32(secret);
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));

            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(timeStep);
            byte[] hash = mac.doFinal(buffer.array());

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", otp);
        } catch (Exception e) {
            return "";
        }
    }

    private String encodeBase32(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0, value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32_CHARS.charAt((value >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(BASE32_CHARS.charAt((value << (5 - bits)) & 31));
        }
        return sb.toString();
    }

    private byte[] decodeBase32(String secret) {
        String cleaned = secret.replace("=", "").toUpperCase();
        ByteBuffer buffer = ByteBuffer.allocate(cleaned.length() * 5 / 8);
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
        return Arrays.copyOf(buffer.array(), buffer.position());
    }

    public record TotpSetupResult(String secret, String otpauthUri, String qrUrl) {}
}
