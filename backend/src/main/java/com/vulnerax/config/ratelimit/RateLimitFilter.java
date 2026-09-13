package com.vulnerax.config.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final int MAX_REQUESTS_PER_HOUR = 1000;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String clientIp = getClientIp(request);
        String key = clientIp + ":" + getMinuteKey();

        RateLimitBucket bucket = buckets.computeIfAbsent(key, k -> new RateLimitBucket(MAX_REQUESTS_PER_MINUTE));

        if (!bucket.tryAcquire()) {
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"success\":false,\"message\":\"Rate limit exceeded. Try again later.\",\"data\":null}");
            return;
        }

        // Hourly limit check
        String hourKey = clientIp + ":" + getHourKey();
        RateLimitBucket hourBucket = buckets.computeIfAbsent(hourKey, k -> new RateLimitBucket(MAX_REQUESTS_PER_HOUR));
        if (!hourBucket.tryAcquire()) {
            log.warn("Hourly rate limit exceeded for IP: {}", clientIp);
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"success\":false,\"message\":\"Hourly rate limit exceeded.\",\"data\":null}");
            return;
        }

        // Cleanup old buckets periodically
        if (buckets.size() > 10000) {
            buckets.entrySet().removeIf(e -> e.getValue().isEmpty());
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator") || path.startsWith("/api-docs") || path.startsWith("/swagger-ui");
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String getMinuteKey() {
        return String.valueOf(System.currentTimeMillis() / 60000);
    }

    private String getHourKey() {
        return String.valueOf(System.currentTimeMillis() / 3600000);
    }

    private static class RateLimitBucket {
        private final int maxTokens;
        private final AtomicInteger tokens;

        RateLimitBucket(int maxTokens) {
            this.maxTokens = maxTokens;
            this.tokens = new AtomicInteger(maxTokens);
        }

        boolean tryAcquire() {
            int current = tokens.get();
            if (current <= 0) return false;
            return tokens.compareAndSet(current, current - 1);
        }

        boolean isEmpty() {
            return tokens.get() <= 0;
        }
    }
}
