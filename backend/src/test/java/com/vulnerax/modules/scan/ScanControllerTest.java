package com.vulnerax.modules.scan;

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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ScanController.class)
@AutoConfigureMockMvc(addFilters = false)
class ScanControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @MockBean ScanService service;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean com.vulnerax.modules.identity.UserRepository userRepository;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void list_returnsScans() throws Exception {
        Scan s = Scan.builder().scannerType("TRIVY").target("app.jar").build();
        s.setId(UUID.randomUUID());
        when(service.list(any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of(s)));
        mvc.perform(get("/api/v1/scans"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content").isArray())
                .andExpect(jsonPath("$.data.content[0].scannerType").value("TRIVY"));
    }

    @Test
    void list_withProjectId_filter() throws Exception {
        UUID projectId = UUID.randomUUID();
        when(service.list(eq(projectId), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/scans").param("projectId", projectId.toString()))
                .andExpect(status().isOk());
    }

    @Test
    void get_returnsScan() throws Exception {
        UUID id = UUID.randomUUID();
        Scan s = Scan.builder().scannerType("ZAP").target("https://example.com").build();
        s.setId(id);
        when(service.get(id)).thenReturn(s);
        mvc.perform(get("/api/v1/scans/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scannerType").value("ZAP"));
    }

    @Test
    void jobs_returnsScanJobs() throws Exception {
        UUID id = UUID.randomUUID();
        ScanJob job = ScanJob.builder().scannerPlugin("sast-plugin").status("COMPLETED").scanId(id).progress(100).build();
        job.setId(UUID.randomUUID());
        when(service.jobs(id)).thenReturn(List.of(job));
        mvc.perform(get("/api/v1/scans/" + id + "/jobs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data[0].scannerPlugin").value("sast-plugin"));
    }

    @Test
    void jobs_emptyList() throws Exception {
        UUID id = UUID.randomUUID();
        when(service.jobs(id)).thenReturn(List.of());
        mvc.perform(get("/api/v1/scans/" + id + "/jobs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data", hasSize(0)));
    }

    @Test
    void create_triggersScan() throws Exception {
        Scan saved = Scan.builder().scannerType("SAST").target("app.jar").status("QUEUED").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        mvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("scannerType", "SAST", "target", "app.jar"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scannerType").value("SAST"))
                .andExpect(jsonPath("$.data.status").value("QUEUED"));
    }

    @Test
    void create_withNullAuth_usesSystem() throws Exception {
        Scan saved = Scan.builder().scannerType("DAST").target("https://example.com").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), eq("system"))).thenReturn(saved);
        mvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("scannerType", "DAST", "target", "https://example.com"))))
                .andExpect(status().isOk());
    }

    @Test
    void cancel_returnsOk() throws Exception {
        UUID id = UUID.randomUUID();
        mvc.perform(post("/api/v1/scans/" + id + "/cancel"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Cancelled"));
        verify(service).cancel(id);
    }

    @Test
    void upload_triggersScanFromFile() throws Exception {
        UUID pid = UUID.randomUUID();
        Scan saved = Scan.builder().scannerType("SAST").target("test.py").status("QUEUED").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        MockMultipartFile file = new MockMultipartFile("file", "test.py", "text/plain", "print('hello')".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file)
                        .param("projectId", pid.toString())
                        .param("scannerType", "SAST"))
                .andExpect(status().isOk());
    }

    @Test
    void upload_withProfile() throws Exception {
        UUID pid = UUID.randomUUID();
        Scan saved = Scan.builder().scannerType("DAST").target("app.js").profile("DEEP").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        MockMultipartFile file = new MockMultipartFile("file", "app.js", "text/javascript", "console.log('hi')".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file)
                        .param("projectId", pid.toString())
                        .param("scannerType", "DAST")
                        .param("profile", "DEEP"))
                .andExpect(status().isOk());
    }

    @Test
    void upload_withAssetId() throws Exception {
        UUID pid = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Scan saved = Scan.builder().scannerType("SAST").target("main.go").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        MockMultipartFile file = new MockMultipartFile("file", "main.go", "text/plain", "package main".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file)
                        .param("projectId", pid.toString())
                        .param("scannerType", "SAST")
                        .param("assetId", assetId.toString()))
                .andExpect(status().isOk());
    }

    @Test
    void upload_withoutProfile_defaultsToStandard() throws Exception {
        UUID pid = UUID.randomUUID();
        when(service.create(any(Scan.class), any())).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            assertEquals("STANDARD", s.getProfile());
            s.setId(UUID.randomUUID());
            return s;
        });
        MockMultipartFile file = new MockMultipartFile("file", "app.py", "text/plain", "import os".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file)
                        .param("projectId", pid.toString())
                        .param("scannerType", "SAST"))
                .andExpect(status().isOk());
    }

    @Test
    void upload_escapesFileContentInConfigJson() throws Exception {
        UUID pid = UUID.randomUUID();
        when(service.create(any(Scan.class), any())).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            assertTrue(s.getConfigJson().contains("fileContent"));
            s.setId(UUID.randomUUID());
            return s;
        });
        MockMultipartFile file = new MockMultipartFile("file", "test.java", "text/plain", "String s = \"hello\"".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file)
                        .param("projectId", pid.toString())
                        .param("scannerType", "SAST"))
                .andExpect(status().isOk());
    }

    @Test
    void list_emptyPage() throws Exception {
        when(service.list(any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        mvc.perform(get("/api/v1/scans"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content", hasSize(0)));
    }

    @Test
    void create_withAllBodyFields() throws Exception {
        Scan saved = Scan.builder().scannerType("SECRET").target("repo").profile("DEEP").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        String body = om.writeValueAsString(Map.of(
                "scannerType", "SECRET", "target", "repo", "profile", "DEEP",
                "configJson", "{\"timeout\":600}"
        ));
        mvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());
    }

    @Test
    void cancel_multipleTimes() throws Exception {
        UUID id = UUID.randomUUID();
        mvc.perform(post("/api/v1/scans/" + id + "/cancel"))
                .andExpect(status().isOk());
        verify(service, times(1)).cancel(id);
    }

    @Test
    void jobs_multipleJobs() throws Exception {
        UUID id = UUID.randomUUID();
        ScanJob j1 = ScanJob.builder().scannerPlugin("sast-plugin").status("COMPLETED").scanId(id).progress(100).build();
        j1.setId(UUID.randomUUID());
        ScanJob j2 = ScanJob.builder().scannerPlugin("secret-plugin").status("RUNNING").scanId(id).progress(50).build();
        j2.setId(UUID.randomUUID());
        when(service.jobs(id)).thenReturn(List.of(j1, j2));
        mvc.perform(get("/api/v1/scans/" + id + "/jobs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data", hasSize(2)));
    }
}
