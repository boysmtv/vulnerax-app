package com.vulnerax.modules.asset;

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

@WebMvcTest(AssetController.class)
@AutoConfigureMockMvc(addFilters = false)
class AssetControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @MockBean AssetService service;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    // list flow
    @Test
    void list_returns_page() throws Exception {
        Asset a = Asset.builder().name("api.example.com").type("DOMAIN").build();
        a.setId(UUID.randomUUID());
        when(service.list(any(), any(), any(), any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of(a)));
        mvc.perform(get("/api/v1/assets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content").isArray());
    }

    @Test
    void get_returns_asset() throws Exception {
        UUID id = UUID.randomUUID();
        Asset a = Asset.builder().name("db01").type("DATABASE").build();
        a.setId(id);
        when(service.get(id)).thenReturn(a);
        mvc.perform(get("/api/v1/assets/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("db01"));
    }

    @Test
    void create_persists_asset() throws Exception {
        Asset saved = Asset.builder().name("new-app").type("WEB_APP").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Asset.class))).thenReturn(saved);
        mvc.perform(post("/api/v1/assets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("name","new-app","type","WEB_APP"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("new-app"));
    }

    @Test
    void update_patches_asset() throws Exception {
        UUID id = UUID.randomUUID();
        Asset updated = Asset.builder().name("patched").type("DOMAIN").criticality("CRITICAL").build();
        updated.setId(id);
        when(service.update(eq(id), any(Asset.class))).thenReturn(updated);
        mvc.perform(put("/api/v1/assets/" + id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("criticality","CRITICAL"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.criticality").value("CRITICAL"));
    }

    @Test
    void delete_returns_ok() throws Exception {
        UUID id = UUID.randomUUID();
        mvc.perform(delete("/api/v1/assets/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void stats_returns_aggregates() throws Exception {
        when(service.stats(any())).thenReturn(Map.of("total", 10, "internetExposed", 3));
        mvc.perform(get("/api/v1/assets/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(10));
    }

    @Test
    void discover_creates_shadow_assets() throws Exception {
        UUID pid = UUID.randomUUID();
        when(service.discoverMock(eq(pid), any())).thenReturn(List.of(Asset.builder().name("shadow.example.com").type("SUBDOMAIN").build()));
        mvc.perform(post("/api/v1/assets/discover").param("projectId", pid.toString()).param("source","MANUAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
}
