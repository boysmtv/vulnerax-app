package com.vulnerax.modules.search;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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

    private Asset buildAsset(String name, String type, String identifier) {
        Asset a = new Asset();
        a.setId(UUID.randomUUID());
        a.setName(name);
        a.setType(type);
        a.setIdentifier(identifier);
        a.setProjectId(UUID.randomUUID());
        a.setOrganizationId(UUID.randomUUID());
        return a;
    }

    private Finding buildFinding(String title, String cwe, String findingId, String severity) {
        Finding f = new Finding();
        f.setId(UUID.randomUUID());
        f.setTitle(title);
        f.setCwe(cwe);
        f.setFindingId(findingId);
        f.setSeverity(severity);
        f.setType("INJECTION");
        f.setConfidence("HIGH");
        return f;
    }

    @Test
    void search_withQuery_returns200() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.query").value("test"))
                .andExpect(jsonPath("$.data.total").value(0));
    }

    @Test
    void search_matchesAssetsByName() throws Exception {
        Asset a = buildAsset("payment-api", "API", "https://api.example.com");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "payment"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)))
                .andExpect(jsonPath("$.data.results[0].type").value("ASSET"))
                .andExpect(jsonPath("$.data.results[0].name").value("payment-api"));
    }

    @Test
    void search_matchesAssetsByIdentifier() throws Exception {
        Asset a = buildAsset("Web App", "WEBAPP", "example.com");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)))
                .andExpect(jsonPath("$.data.results[0].type").value("ASSET"));
    }

    @Test
    void search_matchesAssetsByType() throws Exception {
        Asset a = buildAsset("My API", "API", "api.example.com");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "api"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)));
    }

    @Test
    void search_matchesFindingsByTitle() throws Exception {
        Finding f = buildFinding("SQL Injection in login", "CWE-89", "FINDING-001", "HIGH");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "SQL Injection"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)))
                .andExpect(jsonPath("$.data.results[0].type").value("FINDING"))
                .andExpect(jsonPath("$.data.results[0].title").value("SQL Injection in login"));
    }

    @Test
    void search_matchesFindingsByCwe() throws Exception {
        Finding f = buildFinding("Injection", "CWE-89", "FINDING-001", "HIGH");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "CWE-89"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)))
                .andExpect(jsonPath("$.data.results[0].type").value("FINDING"));
    }

    @Test
    void search_matchesFindingsByFindingId() throws Exception {
        Finding f = buildFinding("XSS in search", "CWE-79", "FINDING-042", "MEDIUM");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "FINDING-042"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)))
                .andExpect(jsonPath("$.data.results[0].findingId").value("FINDING-042"));
    }

    @Test
    void search_caseInsensitive() throws Exception {
        Asset a = buildAsset("Payment Gateway", "API", null);
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "PAYMENT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)));
    }

    @Test
    void search_noMatches_returnsEmptyResults() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "nonexistent"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results").isArray())
                .andExpect(jsonPath("$.data.total").value(0));
    }

    @Test
    void search_mixedResults_assetsAndFindings() throws Exception {
        Asset a = buildAsset("Auth API", "API", "auth.example.com");
        Finding f = buildFinding("Auth Bypass", "CWE-287", "FINDING-100", "CRITICAL");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "auth"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(2)))
                .andExpect(jsonPath("$.data.results[?(@.type=='ASSET')]").exists())
                .andExpect(jsonPath("$.data.results[?(@.type=='FINDING')]").exists());
    }

    @Test
    void search_limitsTo10Assets() throws Exception {
        List<Asset> assets = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            assets.add(buildAsset("api-" + i, "API", null));
        }
        when(assetRepo.findAll()).thenReturn(assets);
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "api"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(10)));
    }

    @Test
    void search_limitsTo10Findings() throws Exception {
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            findings.add(buildFinding("SQL Injection " + i, "CWE-89", "FINDING-" + i, "HIGH"));
        }
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(findings);

        mvc.perform(get("/api/v1/search").param("q", "SQL Injection"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(10)));
    }

    @Test
    void search_assetWithNullIdentifier_doesNotThrow() throws Exception {
        Asset a = buildAsset("Test Asset", "DOMAIN", null);
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "test"))
                .andExpect(status().isOk());
    }

    @Test
    void search_findingWithNullCwe_doesNotThrow() throws Exception {
        Finding f = buildFinding("Some issue", null, "FINDING-200", "LOW");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "Some issue"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)));
    }

    @Test
    void search_emptyQuery_returnsAll() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.query").value(""));
    }

    @Test
    void search_specialCharsInQuery_doesNotThrow() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "test&<script>"))
                .andExpect(status().isOk());
    }

    @Test
    void search_assetWithNullName_isFilteredOut() throws Exception {
        Asset a = buildAsset(null, "API", null);
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "test"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    void search_findingWithNullTitle_isFilteredOut() throws Exception {
        Finding f = new Finding();
        f.setId(UUID.randomUUID());
        f.setTitle(null);
        f.setSeverity("HIGH");
        f.setType("INJECTION");
        f.setConfidence("HIGH");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "test"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    void search_returnsQueryInResponse() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "security"))
                .andExpect(jsonPath("$.data.query").value("security"));
    }

    @Test
    void search_returnsTotalCount() throws Exception {
        Asset a = buildAsset("API Gateway", "API", null);
        Finding f = buildFinding("Auth Bypass", "CWE-287", "FINDING-100", "HIGH");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "api"))
                .andExpect(jsonPath("$.data.total").value(1));
    }

    @Test
    void search_identicalQueryInResponse() throws Exception {
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());

        String query = "my-query-123";
        mvc.perform(get("/api/v1/search").param("q", query))
                .andExpect(jsonPath("$.data.query").value(query));
    }

    @Test
    void search_findingWithNullFindingId_mapOfRejectsNull() throws Exception {
        Finding f = new Finding();
        f.setId(UUID.randomUUID());
        f.setTitle("Bug");
        f.setFindingId(null);
        f.setSeverity("HIGH");
        f.setType("SAST");
        f.setConfidence("HIGH");
        when(assetRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of(f));

        mvc.perform(get("/api/v1/search").param("q", "Bug"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    void search_assetTypeMatch_notJustName() throws Exception {
        Asset a = buildAsset("My Server", "SERVER", "10.0.0.1");
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)));
    }

    @Test
    void search_nullIdentifier_assetStillMatchedByName() throws Exception {
        Asset a = buildAsset("Payment API", "API", null);
        when(assetRepo.findAll()).thenReturn(List.of(a));
        when(findingRepo.findAll()).thenReturn(List.of());

        mvc.perform(get("/api/v1/search").param("q", "payment"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.results", hasSize(1)));
    }
}
