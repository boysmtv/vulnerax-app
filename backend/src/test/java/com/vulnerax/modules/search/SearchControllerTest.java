package com.vulnerax.modules.search;

import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SearchController.class)
@AutoConfigureMockMvc(addFilters = false)
class SearchControllerTest {

    @Autowired MockMvc mvc;
    @MockBean AssetRepository assetRepo;
    @MockBean FindingRepository findingRepo;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void list_or_get_returns_ok_or_not_found_but_controller_loads() throws Exception {
        when(assetRepo.findAll()).thenReturn(java.util.List.of());
        when(findingRepo.findAll()).thenReturn(java.util.List.of());
        mvc.perform(get("/api/v1/search").param("q", "test")).andExpect(result -> {
            int s = result.getResponse().getStatus();
            String body = result.getResponse().getContentAsString(); assert s == 200 : "search should be 200 but got " + s + " " + body;
        });
    }

    @Test
    void context_loads() throws Exception {
        when(assetRepo.findAll()).thenReturn(java.util.List.of());
        when(findingRepo.findAll()).thenReturn(java.util.List.of());
        mvc.perform(get("/api/v1/search").param("q", "test")).andExpect(result -> {
            int s = result.getResponse().getStatus(); assert s == 200;
        });
    }
}
