package com.vulnerax.modules.dashboard;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class DashboardIntegrationTest {

    @Autowired MockMvc mvc;

    @Test
    void posture_returns_securityScore_and_critical() throws Exception {
        mvc.perform(get("/api/v1/dashboard/posture"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.securityScore").exists())
                .andExpect(jsonPath("$.data.critical").exists())
                .andExpect(jsonPath("$.data.totalAssets").exists());
    }

    @Test
    void posture_with_projectId_returns_same_shape() throws Exception {
        mvc.perform(get("/api/v1/dashboard/posture").param("projectId", "00000000-0000-0000-0000-000000000001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.securityScore").exists());
    }

    @Test
    void application_dashboard_returns_project_view() throws Exception {
        mvc.perform(get("/api/v1/dashboard/application/00000000-0000-0000-0000-000000000001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.projectId").value("00000000-0000-0000-0000-000000000001"));
    }
}
