package com.vulnerax;

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
class ApiSmokeTest {

    @Autowired MockMvc mvc;

    @Test
    void all_critical_apis_return_200_and_no_500() throws Exception {
        mvc.perform(get("/api/v1/auth/sso/providers")).andExpect(status().isOk());
        mvc.perform(get("/api/v1/assets/stats")).andExpect(status().isOk()).andExpect(jsonPath("$.data.total").exists());
        mvc.perform(get("/api/v1/dashboard/posture")).andExpect(status().isOk()).andExpect(jsonPath("$.data.securityScore").exists());
        mvc.perform(get("/api/v1/graph/attack-paths").param("projectId", "00000000-0000-0000-0000-000000000001")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            assert s != 500;
        });
    }

    @Test
    void dashboard_no_bug_on_empty_db() throws Exception {
        mvc.perform(get("/api/v1/dashboard/posture")).andExpect(status().isOk())
                .andExpect(jsonPath("$.data.coverage").exists())
                .andExpect(jsonPath("$.data.trend").isArray());
    }
}
