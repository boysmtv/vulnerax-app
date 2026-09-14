package com.vulnerax.modules.finding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnerax.common.PageResponse;
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

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
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

    private Finding buildFinding(String title, String type, String severity) {
        Finding f = Finding.builder().title(title).type(type).severity(severity).confidence("HIGH").build();
        f.setId(UUID.randomUUID());
        f.setFindingId("FND-1001");
        return f;
    }

    @Test
    void list_returnsPage() throws Exception {
        Finding f = buildFinding("SQLi", "INJECTION", "HIGH");
        when(service.list(any(), any(), any(), any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(f)));
        mvc.perform(get("/api/v1/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].title").value("SQLi"));
    }

    @Test
    void list_withProjectId_filter() throws Exception {
        UUID projectId = UUID.randomUUID();
        when(service.list(eq(projectId), any(), any(), any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("projectId", projectId.toString()))
                .andExpect(status().isOk());
    }

    @Test
    void list_withAssetId_filter() throws Exception {
        UUID assetId = UUID.randomUUID();
        when(service.list(any(), eq(assetId), any(), any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("assetId", assetId.toString()))
                .andExpect(status().isOk());
    }

    @Test
    void list_withSeverity_filter() throws Exception {
        when(service.list(any(), any(), eq("CRITICAL"), any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("severity", "CRITICAL"))
                .andExpect(status().isOk());
    }

    @Test
    void list_withStatus_filter() throws Exception {
        when(service.list(any(), any(), any(), eq("OPEN"), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("status", "OPEN"))
                .andExpect(status().isOk());
    }

    @Test
    void list_withRiskLevel_filter() throws Exception {
        when(service.list(any(), any(), any(), any(), eq("CRITICAL"), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("riskLevel", "CRITICAL"))
                .andExpect(status().isOk());
    }

    @Test
    void list_withSearch_filter() throws Exception {
        when(service.list(any(), any(), any(), any(), any(), eq("injection"), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings").param("search", "injection"))
                .andExpect(status().isOk());
    }

    @Test
    void get_returnsFinding() throws Exception {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("BOLA", "AUTHORIZATION", "HIGH");
        f.setId(id);
        when(service.get(id)).thenReturn(f);
        mvc.perform(get("/api/v1/findings/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("BOLA"));
    }

    @Test
    void create_insertsFinding() throws Exception {
        Finding saved = buildFinding("XSS", "XSS", "MEDIUM");
        when(service.create(any(Finding.class))).thenReturn(saved);
        mvc.perform(post("/api/v1/findings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("title", "XSS", "type", "XSS", "severity", "MEDIUM", "confidence", "HIGH"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("XSS"));
    }

    @Test
    void updateStatus_changesState() throws Exception {
        UUID id = UUID.randomUUID();
        Finding updated = buildFinding("XSS", "XSS", "MEDIUM");
        updated.setId(id);
        updated.setStatus("RESOLVED");
        when(service.updateStatus(eq(id), eq("RESOLVED"), any())).thenReturn(updated);
        mvc.perform(put("/api/v1/findings/" + id + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("status", "RESOLVED", "comment", "fixed"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("RESOLVED"));
    }

    @Test
    void updateStatus_toFalsePositive() throws Exception {
        UUID id = UUID.randomUUID();
        Finding updated = buildFinding("Bug", "SAST", "LOW");
        updated.setId(id);
        updated.setStatus("FALSE_POSITIVE");
        when(service.updateStatus(eq(id), eq("FALSE_POSITIVE"), any())).thenReturn(updated);
        mvc.perform(put("/api/v1/findings/" + id + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("status", "FALSE_POSITIVE", "comment", "not a bug"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("FALSE_POSITIVE"));
    }

    @Test
    void updateStatus_toRiskAccepted() throws Exception {
        UUID id = UUID.randomUUID();
        Finding updated = buildFinding("Bug", "SCA", "HIGH");
        updated.setId(id);
        updated.setStatus("RISK_ACCEPTED");
        when(service.updateStatus(eq(id), eq("RISK_ACCEPTED"), any())).thenReturn(updated);
        mvc.perform(put("/api/v1/findings/" + id + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("status", "RISK_ACCEPTED", "comment", "accepted"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("RISK_ACCEPTED"));
    }

    @Test
    void evidences_returnsList() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.evidences(id)).thenReturn(List.of(
                Evidence.builder().type("SCANNER_RESULT").content("ev1").build(),
                Evidence.builder().type("CODE_SNIPPET").content("ev2").build()
        ));
        mvc.perform(get("/api/v1/findings/" + id + "/evidence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data", hasSize(2)));
    }

    @Test
    void evidences_emptyList() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.evidences(id)).thenReturn(List.of());
        mvc.perform(get("/api/v1/findings/" + id + "/evidence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data", hasSize(0)));
    }

    @Test
    void instances_returnsList() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.instances(id)).thenReturn(List.of(
                FindingInstance.builder().assetName("Web App").location("/src/Main.java:1").build()
        ));
        mvc.perform(get("/api/v1/findings/" + id + "/instances"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data", hasSize(1)));
    }

    @Test
    void stats_aggregates() throws Exception {
        when(service.stats(any())).thenReturn(Map.of(
                "total", 5,
                "bySeverity", Map.of("HIGH", 2, "MEDIUM", 3),
                "critical", 1,
                "high", 2,
                "kev", 0,
                "avgRiskScore", 45.5
        ));
        mvc.perform(get("/api/v1/findings/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(5))
                .andExpect(jsonPath("$.data.critical").value(1));
    }

    @Test
    void stats_withProjectId() throws Exception {
        UUID projectId = UUID.randomUUID();
        when(service.stats(projectId)).thenReturn(Map.of("total", 3));
        mvc.perform(get("/api/v1/findings/stats").param("projectId", projectId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(3));
    }

    @Test
    void correlation_returnsAttackPath() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.correlation(id)).thenReturn(Map.of(
                "finding", Map.of("id", id, "title", "XSS"),
                "correlated", List.of(),
                "correlation", Map.of("reason", "NO_MATCH", "isDuplicate", false, "matchCount", 0)
        ));
        mvc.perform(get("/api/v1/findings/" + id + "/correlation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.finding.title").value("XSS"));
    }

    @Test
    void correlation_withMatches() throws Exception {
        UUID id = UUID.randomUUID();
        UUID matchId = UUID.randomUUID();
        when(service.correlation(id)).thenReturn(Map.of(
                "finding", Map.of("id", id, "title", "SQLi"),
                "correlated", List.of(Map.of("id", matchId, "title", "SQLi Variant", "severity", "HIGH")),
                "correlation", Map.of("reason", "EXACT_MATCH", "isDuplicate", true, "matchCount", 1),
                "attackPathCandidate", Map.of("chain", List.of("INJECTION", "INJECTION"), "riskMultiplier", 0.3)
        ));
        mvc.perform(get("/api/v1/findings/" + id + "/correlation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.correlated", hasSize(1)))
                .andExpect(jsonPath("$.data.attackPathCandidate").exists());
    }

    @Test
    void list_emptyPage() throws Exception {
        when(service.list(any(), any(), any(), any(), any(), any(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content").isArray())
                .andExpect(jsonPath("$.data.content", hasSize(0)));
    }

    @Test
    void get_withMultipleFindings() throws Exception {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();
        Finding f1 = buildFinding("SQLi", "INJECTION", "CRITICAL");
        f1.setId(id1);
        Finding f2 = buildFinding("XSS", "XSS", "MEDIUM");
        f2.setId(id2);
        when(service.get(id1)).thenReturn(f1);
        when(service.get(id2)).thenReturn(f2);

        mvc.perform(get("/api/v1/findings/" + id1))
                .andExpect(jsonPath("$.data.title").value("SQLi"));
        mvc.perform(get("/api/v1/findings/" + id2))
                .andExpect(jsonPath("$.data.title").value("XSS"));
    }

    @Test
    void create_withFullBody() throws Exception {
        Finding saved = buildFinding("New Finding", "SECRET", "HIGH");
        when(service.create(any(Finding.class))).thenReturn(saved);
        String body = om.writeValueAsString(Map.of(
                "title", "New Finding", "type", "SECRET", "severity", "HIGH", "confidence", "HIGH",
                "description", "Hardcoded API key found",
                "filePath", "/src/config.java",
                "lineNumber", 15
        ));
        mvc.perform(post("/api/v1/findings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("New Finding"));
    }

    @Test
    void updateStatus_withNullComment() throws Exception {
        UUID id = UUID.randomUUID();
        Finding updated = buildFinding("Bug", "SAST", "LOW");
        updated.setId(id);
        updated.setStatus("RESOLVED");
        when(service.updateStatus(eq(id), eq("RESOLVED"), isNull())).thenReturn(updated);
        mvc.perform(put("/api/v1/findings/" + id + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("status", "RESOLVED"))))
                .andExpect(status().isOk());
    }

    @Test
    void instances_emptyList() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.instances(id)).thenReturn(List.of());
        mvc.perform(get("/api/v1/findings/" + id + "/instances"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data", hasSize(0)));
    }
}
