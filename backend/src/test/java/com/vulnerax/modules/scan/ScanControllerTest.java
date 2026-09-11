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
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
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

    // run flow — create scan
    @Test
    void create_triggers_scan() throws Exception {
        Scan saved = Scan.builder().scannerType("SEMGREP").profile("STANDARD").target("app.jar").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        mvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(java.util.Map.of("scannerType","SEMGREP","target","app.jar"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scannerType").value("SEMGREP"));
    }

    @Test
    void list_returns_scans() throws Exception {
        Scan s = Scan.builder().scannerType("TRIVY").build();
        s.setId(UUID.randomUUID());
        when(service.list(any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of(s)));
        mvc.perform(get("/api/v1/scans"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content").isArray());
    }

    @Test
    void get_returns_scan() throws Exception {
        UUID id = UUID.randomUUID();
        Scan s = Scan.builder().scannerType("ZAP").build();
        s.setId(id);
        when(service.get(id)).thenReturn(s);
        mvc.perform(get("/api/v1/scans/" + id))
                .andExpect(status().isOk());
    }

    @Test
    void jobs_returns_scan_jobs() throws Exception {
        UUID id = UUID.randomUUID();
        ScanJob job = ScanJob.builder().scannerPlugin("semgrep").status("COMPLETED").scanId(UUID.randomUUID()).build();
        job.setId(UUID.randomUUID());
        when(service.jobs(id)).thenReturn(List.of(job));
        mvc.perform(get("/api/v1/scans/" + id + "/jobs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    void cancel_returns_ok() throws Exception {
        UUID id = UUID.randomUUID();
        mvc.perform(post("/api/v1/scans/" + id + "/cancel"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    // start flow — upload scan file
    @Test
    void upload_triggers_scan_from_file() throws Exception {
        UUID pid = UUID.randomUUID();
        Scan saved = Scan.builder().scannerType("SEMGREP").target("test.py").build();
        saved.setId(UUID.randomUUID());
        when(service.create(any(Scan.class), any())).thenReturn(saved);
        var file = new org.springframework.mock.web.MockMultipartFile("file", "test.py", "text/plain", "print('hi')".getBytes());
        mvc.perform(multipart("/api/v1/scans/upload").file(file).param("projectId", pid.toString()).param("scannerType","SEMGREP"))
                .andExpect(status().isOk());
    }
}
