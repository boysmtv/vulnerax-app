package com.vulnerax.modules.scan;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScanControllerUnitTest {

    @Mock ScanService service;
    @InjectMocks ScanController controller;

    private UUID projectId;
    private UUID scanId;
    private Scan scan;

    @BeforeEach
    void setUp() {
        projectId = UUID.randomUUID();
        scanId = UUID.randomUUID();
        scan = Scan.builder().projectId(projectId).scannerType("SAST").scanType("SAST")
                .profile("STANDARD").target("https://example.com").build();
    }

    @Test
    void list_returnsPage() {
        when(service.list(eq(projectId), any())).thenReturn(new PageImpl<>(List.of(scan)));
        var res = controller.list(projectId, PageRequest.of(0, 20));
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void get_returnsScan() {
        when(service.get(scanId)).thenReturn(scan);
        var res = controller.get(scanId);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void jobs_returnsJobs() {
        when(service.jobs(scanId)).thenReturn(List.of());
        var res = controller.jobs(scanId);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void create_nullAuth_usesSystem() {
        when(service.create(any(Scan.class), eq("system"))).thenReturn(scan);
        var res = controller.create(scan, null);
        assertThat(res.isSuccess()).isTrue();
        verify(service).create(any(), eq("system"));
    }

    @Test
    void create_withAuth_usesName() {
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("alice");
        when(service.create(any(Scan.class), eq("alice"))).thenReturn(scan);
        var res = controller.create(scan, auth);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void upload_defaultProfile_usesStandard() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "app.java",
                "text/plain", "password=\"secret\"\nline2\\end".getBytes());
        when(service.create(any(Scan.class), eq("system"))).thenReturn(scan);
        var res = controller.upload(projectId, "SAST", null, null, file, null);
        assertThat(res.isSuccess()).isTrue();
        verify(service).create(argThat((Scan s) ->
                "STANDARD".equals(s.getProfile()) && s.getConfigJson().contains("\\n") && s.getConfigJson().contains("\\\"")), eq("system"));
    }

    @Test
    void upload_withProfileAndAuth() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "main.py",
                "text/plain", "print(1)".getBytes());
        Authentication auth = mock(Authentication.class);
        when(auth.getName()).thenReturn("bob");
        UUID assetId = UUID.randomUUID();
        when(service.create(any(Scan.class), eq("bob"))).thenReturn(scan);
        var res = controller.upload(projectId, "SAST", "DEEP", assetId, file, auth);
        assertThat(res.isSuccess()).isTrue();
        verify(service).create(argThat((Scan s) ->
                "DEEP".equals(s.getProfile()) && assetId.equals(s.getAssetId())), eq("bob"));
    }

    @Test
    void cancel_callsService() {
        doNothing().when(service).cancel(scanId);
        var res = controller.cancel(scanId);
        assertThat(res.isSuccess()).isTrue();
        verify(service).cancel(scanId);
    }
}
