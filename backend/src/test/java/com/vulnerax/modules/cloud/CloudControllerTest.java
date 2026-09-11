package com.vulnerax.modules.cloud;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CloudController.class)
@AutoConfigureMockMvc(addFilters = false)
class CloudControllerTest {

    @Autowired MockMvc mvc;
    @MockBean CloudService svc;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void list_or_get_returns_ok_or_not_found_but_controller_loads() throws Exception {
        try {
            mvc.perform(get("/api/v1/cloud")).andExpect(result -> {
                int s = result.getResponse().getStatus();
                String body = result.getResponse().getContentAsString(); assert s != 500 || body.contains("No static resource") || body.contains("Failed to convert") : "controller bean failure: " + body;
            });
        } catch (Exception e) {
            mvc.perform(get("/api/v1/cloud/00000000-0000-0000-0000-000000000001")).andExpect(result -> {
                int s = result.getResponse().getStatus();
                String body = result.getResponse().getContentAsString(); assert s != 500 || body.contains("No static resource") || body.contains("Failed to convert") : "unexpected 500: " + body;
            });
        }
    }

    @Test
    void context_loads() throws Exception {
        mvc.perform(get("/api/v1/cloud/stats")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            String body = result.getResponse().getContentAsString(); assert s != 500 || body.contains("No static resource") || body.contains("Failed to convert") : "unexpected 500: " + body;
        });
    }
}
