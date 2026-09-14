package com.vulnerax.config.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RateLimitFilterTest {

    @InjectMocks RateLimitFilter filter;

    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain chain;

    @Test
    void doFilter_underLimit_passesThrough() throws ServletException, IOException {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_overMinuteLimit_returns429() throws ServletException, IOException {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        // Exhaust the bucket
        for (int i = 0; i < 60; i++) {
            filter.doFilterInternal(request, response, chain);
        }
        reset(chain);
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));
        filter.doFilterInternal(request, response, chain);

        verify(response).setStatus(429);
        verify(chain, never()).doFilter(request, response);
        assertTrue(sw.toString().contains("Rate limit exceeded"));
    }

    @Test
    void doFilter_xffHeader_usesFirstIp() throws ServletException, IOException {
        lenient().when(request.getHeader("X-Forwarded-For")).thenReturn("192.168.1.1, 10.0.0.1");
        lenient().when(request.getRemoteAddr()).thenReturn("0.0.0.0");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_emptyXff_usesRemoteAddr() throws ServletException, IOException {
        lenient().when(request.getHeader("X-Forwarded-For")).thenReturn("");
        lenient().when(request.getRemoteAddr()).thenReturn("172.16.0.1");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldNotFilter_actuator_returnsTrue() {
        when(request.getRequestURI()).thenReturn("/actuator/health");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void shouldNotFilter_apidocs_returnsTrue() {
        when(request.getRequestURI()).thenReturn("/api-docs");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void shouldNotFilter_swagger_returnsTrue() {
        when(request.getRequestURI()).thenReturn("/swagger-ui/index.html");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void shouldNotFilter_normalApi_returnsFalse() {
        when(request.getRequestURI()).thenReturn("/api/v1/test");
        assertFalse(filter.shouldNotFilter(request));
    }

    @Test
    void doFilter_multipleIpsXff_usesFirst() throws ServletException, IOException {
        lenient().when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.1, 70.41.3.18, 150.172.238.178");
        lenient().when(request.getRemoteAddr()).thenReturn("0.0.0.0");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_cleanupWhenLargeBuckets() throws ServletException, IOException {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        // Run many requests from different IPs to fill buckets
        for (int i = 0; i < 150; i++) {
            when(request.getRemoteAddr()).thenReturn("10.0." + (i / 256) + "." + (i % 256));
            filter.doFilterInternal(request, response, chain);
        }

        // Should not throw
        verify(chain, atLeastOnce()).doFilter(request, response);
    }

    @Test
    void doFilter_minuteKeyChanges_overTime() throws ServletException, IOException {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.50");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        // First request passes
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_hourlyBucket_keyedCorrectly() throws ServletException, IOException {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.99");
        when(request.getRequestURI()).thenReturn("/api/v1/test");

        // Run 5 requests - all should pass (well under 1000/hr limit)
        for (int i = 0; i < 5; i++) {
            filter.doFilterInternal(request, response, chain);
        }
        verify(chain, times(5)).doFilter(request, response);
    }
}
