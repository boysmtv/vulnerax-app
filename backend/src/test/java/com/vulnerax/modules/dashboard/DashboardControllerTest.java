package com.vulnerax.modules.dashboard;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DashboardController.class)
@AutoConfigureMockMvc(addFilters = false)
class DashboardControllerTest {

    @Autowired MockMvc mvc;
    @MockBean DashboardService svc;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void posture_returns_security_score() throws Exception {
        when(svc.securityPosture(any(), any())).thenReturn(Map.of("securityScore", 74, "critical", 3, "high", 17, "totalAssets", 247));
        mvc.perform(get("/api/v1/dashboard/posture"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.securityScore").value(74))
                .andExpect(jsonPath("$.data.critical").value(3));
    }

    @Test
    void application_dashboard_returns_project_view() throws Exception {
        UUID pid = UUID.randomUUID();
        when(svc.applicationDashboard(pid)).thenReturn(Map.of("projectId", pid.toString(), "securityScore", 71));
        mvc.perform(get("/api/v1/dashboard/application/" + pid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.projectId").value(pid.toString()));
    }
}
