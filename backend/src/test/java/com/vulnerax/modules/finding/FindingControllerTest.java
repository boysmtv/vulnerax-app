package com.vulnerax.modules.finding;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(FindingController.class)
@AutoConfigureMockMvc(addFilters = false)
class FindingControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @MockBean FindingService service;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void list_returns_page() throws Exception {
        Finding f = Finding.builder().title("SQLi").type("INJECTION").severity("HIGH").confidence("HIGH").build();
        f.setId(UUID.randomUUID()); f.setFindingId("FND-1001");
        when(service.list(any(), any(), any(), any(), any(), any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of(f)));
        mvc.perform(get("/api/v1/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].title").value("SQLi"));
    }

    @Test
    void get_returns_finding() throws Exception {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().title("BOLA").type("AUTHORIZATION").severity("HIGH").confidence("HIGH").build();
        f.setId(id); f.setFindingId("FND-1002");
        when(service.get(id)).thenReturn(f);
        mvc.perform(get("/api/v1/findings/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("BOLA"));
    }

    @Test
    void create_inserts_finding() throws Exception {
        Finding saved = Finding.builder().title("XSS").type("INJECTION").severity("MEDIUM").confidence("MEDIUM").build();
        saved.setId(UUID.randomUUID()); saved.setFindingId("FND-1003");
        when(service.create(any(Finding.class))).thenReturn(saved);
        mvc.perform(post("/api/v1/findings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("title","XSS","type","INJECTION","severity","MEDIUM","confidence","MEDIUM"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("XSS"));
    }

    @Test
    void updateStatus_changes_state() throws Exception {
        UUID id = UUID.randomUUID();
        Finding updated = Finding.builder().title("XSS").type("INJECTION").severity("MEDIUM").confidence("MEDIUM").status("RESOLVED").build();
        updated.setId(id);
        when(service.updateStatus(eq(id), eq("RESOLVED"), any())).thenReturn(updated);
        mvc.perform(put("/api/v1/findings/" + id + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("status","RESOLVED","comment","fixed"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("RESOLVED"));
    }

    @Test
    void evidences_returns_list() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.evidences(id)).thenReturn(List.of(Evidence.builder().type("SCANNER_RESULT").content("ev").build()));
        mvc.perform(get("/api/v1/findings/" + id + "/evidence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    void stats_aggregates() throws Exception {
        when(service.stats(any())).thenReturn(Map.of("total", 5, "bySeverity", Map.of("HIGH", 2)));
        mvc.perform(get("/api/v1/findings/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(5));
    }

    @Test
    void correlation_returns_attack_path() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.correlation(id)).thenReturn(Map.of("attackPathCandidate","chain"));
        mvc.perform(get("/api/v1/findings/" + id + "/correlation"))
                .andExpect(status().isOk());
    }
}
