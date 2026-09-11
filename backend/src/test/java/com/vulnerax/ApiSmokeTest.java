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
        // auth is permitAll, should be 200 or 400 not 500
        mvc.perform(get("/api/v1/auth/sso/providers")).andExpect(status().isOk());
        // assets stats
        mvc.perform(get("/api/v1/assets/stats")).andExpect(status().isOk()).andExpect(jsonPath("$.data.total").exists());
        // findings stats
        mvc.perform(get("/api/v1/findings/stats")).andExpect(status().isOk()).andExpect(jsonPath("$.data.total").exists());
        // scans list
        mvc.perform(get("/api/v1/scans")).andExpect(status().isOk());
        // dashboard posture
        mvc.perform(get("/api/v1/dashboard/posture")).andExpect(status().isOk()).andExpect(jsonPath("$.data.securityScore").exists());
        // graph
        mvc.perform(get("/api/v1/graph/attack-paths").param("projectId", "00000000-0000-0000-0000-000000000001")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            assert s != 500;
        });
        // search with q
        mvc.perform(get("/api/v1/search").param("q", "test")).andExpect(status().isOk()).andExpect(jsonPath("$.data.results").exists());
        // audit
        mvc.perform(get("/api/v1/audit")).andExpect(status().isOk());
    }

    @Test
    void dashboard_no_bug_on_empty_db() throws Exception {
        // ensures dashboard handles empty finding/asset gracefully (no NPE)
        mvc.perform(get("/api/v1/dashboard/posture")).andExpect(status().isOk())
                .andExpect(jsonPath("$.data.coverage").exists())
                .andExpect(jsonPath("$.data.trend").isArray());
    }
}
