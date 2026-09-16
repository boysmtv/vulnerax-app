package com.vulnerax.modules.oneclick;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetService;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanService;
import com.vulnerax.modules.scan.SecurityCoverageRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(OneClickController.class)
@AutoConfigureMockMvc(addFilters = false)
class OneClickControllerTest {

    @Autowired MockMvc mvc;
    @MockBean OneClickService oneClickService;
    @MockBean ScanService scanService;
    @MockBean AssetService assetService;
    @MockBean SecurityCoverageRegistry coverageRegistry;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    private Authentication mockAuth() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("testuser");
        return auth;
    }

    private void setupScanMocks() {
        Map<String, Object> coverage = Map.of("totalTests", 10, "recommendedTags", List.of("url"));
        when(coverageRegistry.planCoverage(anyString(), anyString())).thenReturn(coverage);
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        when(assetService.createAsset(anyString(), anyString(), anyString())).thenReturn(asset);
        Scan scan = new Scan();
        scan.setId(UUID.randomUUID());
        when(scanService.createScan(anyString(), anyString())).thenReturn(scan);
        doNothing().when(scanService).startScan(any(Scan.class), anyString());
    }

    @Test
    void scan_urlType_returnsOk() throws Exception {
        setupScanMocks();
        mvc.perform(post("/api/v1/scan")
                        .param("targetType", "url")
                        .param("targetUrl", "https://example.com")
                        .principal(mockAuth()))
                .andExpect(status().isOk());
    }

    @Test
    void scan_ipType_returnsOk() throws Exception {
        setupScanMocks();
        mvc.perform(post("/api/v1/scan")
                        .param("targetType", "ip")
                        .param("targetUrl", "192.168.1.1")
                        .principal(mockAuth()))
                .andExpect(status().isOk());
    }

    @Test
    void scan_domainType_returnsOk() throws Exception {
        setupScanMocks();
        mvc.perform(post("/api/v1/scan")
                        .param("targetType", "domain")
                        .param("targetUrl", "example.com")
                        .principal(mockAuth()))
                .andExpect(status().isOk());
    }

    @Test
    void scan_mobileType_returnsOk() throws Exception {
        setupScanMocks();
        mvc.perform(post("/api/v1/scan")
                        .param("targetType", "mobile")
                        .param("targetUrl", "app.apk")
                        .principal(mockAuth()))
                .andExpect(status().isOk());
    }

    @Test
    void plan_urlType_returnsCoverage() throws Exception {
        Map<String, Object> coverage = Map.of("totalTests", 15, "recommendedTags", List.of("url", "sqli"));
        when(coverageRegistry.planCoverage(anyString(), anyString())).thenReturn(coverage);

        mvc.perform(get("/api/v1/plan")
                        .param("targetType", "url")
                        .param("targetUrl", "https://example.com"))
                .andExpect(status().isOk());
    }

    @Test
    void plan_unknownType_returnsDefault() throws Exception {
        Map<String, Object> coverage = Map.of("totalTests", 2);
        when(coverageRegistry.planCoverage(anyString(), anyString())).thenReturn(coverage);

        mvc.perform(get("/api/v1/plan")
                        .param("targetType", "unknown")
                        .param("targetUrl", "something"))
                .andExpect(status().isOk());
    }
}
