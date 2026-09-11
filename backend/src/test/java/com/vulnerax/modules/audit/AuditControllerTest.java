package com.vulnerax.modules.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuditController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuditControllerTest {

    @Autowired MockMvc mvc;
    @MockBean AuditService service;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void list_or_get_returns_ok_or_not_found_but_controller_loads() throws Exception {
        when(service.list(any())).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/audit")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            String body = result.getResponse().getContentAsString(); assert s == 200 : "audit list should be 200 but got " + s + " body " + body;
        });
    }

    @Test
    void context_loads() throws Exception {
        when(service.list(any())).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/audit")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            assert s == 200;
        });
    }
}
