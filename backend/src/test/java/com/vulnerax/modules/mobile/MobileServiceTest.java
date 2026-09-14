package com.vulnerax.modules.mobile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;

import java.io.IOException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MobileServiceTest {

    @Mock MobileRepository repo;
    @InjectMocks MobileService service;

    private UUID projectId = UUID.randomUUID();

    @Test
    void upload_withValidFile() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file", "app.apk", "application/octet-stream", "PKfakeApkContent".getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result).isNotNull();
        assertThat(result.getFileName()).isEqualTo("app.apk");
        assertThat(result.getPlatform()).isEqualTo("ANDROID");
        assertThat(result.getStatus()).isEqualTo("DONE");
        assertThat(result.getFileSha256()).hasSize(64);
        assertThat(result.getFileSize()).isEqualTo(file.getSize());
        verify(repo).save(any());
    }

    @Test
    void upload_withNullFile() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", null);
        assertThat(result.getFileSize()).isEqualTo(0);
        assertThat(result.getStatus()).isEqualTo("DONE");
    }

    @Test
    void upload_withEmptyFileName() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "", "application/octet-stream", new byte[0]);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "", "ANDROID", file);
        assertThat(result.getFileName()).isEqualTo("");
        assertThat(result.getFileSize()).isEqualTo(0);
    }

    @Test
    void upload_withNullPlatform_defaultsToAndroid() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", "data".getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", null, file);
        assertThat(result.getPlatform()).isEqualTo("ANDROID");
    }

    @Test
    void upload_withApkBytes_extractsSecrets() throws IOException {
        String payload = "AKIAIOSFODNN7EXAMPLE https://api.example.com/v1/endpoint "
                + "WebView setJavaScriptEnabled(true) usesCleartextTraffic=\"true\"";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG");
        assertThat(result.getMasvsScore()).isLessThanOrEqualTo(100);
        assertThat(result.getMasvsScore()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void upload_repoThrows_wrapsInRuntime() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", "data".getBytes());
        when(repo.save(any())).thenThrow(new RuntimeException("DB error"));
        assertThatThrownBy(() -> service.upload(projectId, "app.apk", "ANDROID", file))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Mobile analysis failed");
    }

    @Test
    void upload_overload_delegatesToMain() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID");
        assertThat(result.getStatus()).isEqualTo("DONE");
        verify(repo).save(any());
    }

    @Test
    void upload_withWebView_findings() throws IOException {
        String payload = "WebView setJavaScriptEnabled(true) setAllowFileAccess(true)";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG-PLATFORM-7");
    }

    @Test
    void upload_withCleartextTraffic_findsCleartext() throws IOException {
        String payload = "usesCleartextTraffic=\"true\"";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG-NETWORK-1");
    }

    @Test
    void upload_withExportedComponent_findsExported() throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(baos)) {
            zos.putNextEntry(new java.util.zip.ZipEntry("AndroidManifest.xml"));
            zos.write("exported=\"true\" INTERNET".getBytes());
            zos.closeEntry();
        }
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", baos.toByteArray());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG-PLATFORM-2");
    }

    @Test
    void upload_apkWithNoBytes_findsNoInfoFinding() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", new byte[0]);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG-INFO");
    }

    @Test
    void upload_withHttpUrl_findsCleartextFromHttp() throws IOException {
        String payload = "http://example.com/api/data";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("MSTG-NETWORK-1");
    }

    @Test
    void upload_noSecretsAndNoWebView_noSecurityFindings() throws IOException {
        String payload = "Just some harmless text without any patterns";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getMasvsScore()).isEqualTo(100);
    }

    @Test
    void upload_withEndpoints_extractedFromContent() throws IOException {
        String payload = "https://api.example.com/v1/data https://login.example.com/auth";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getStringsJson()).contains("https://");
    }

    @Test
    void upload_platformIOS() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.ipa", "application/octet-stream", "IPAContent".getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.ipa", "IOS", file);
        assertThat(result.getPlatform()).isEqualTo("IOS");
    }

    @Test
    void upload_nullFileBytes_apkName_findsNoInfo() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", new byte[0]);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getFindingsJson()).isNotEmpty();
    }

    @Test
    void upload_nonApkNoBytes_noFinding() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.exe", "application/octet-stream", new byte[0]);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.exe", "ANDROID", file);
        assertThat(result.getFindingsJson()).contains("[]");
    }

    // --- list ---

    @Test
    void list_withProjectId() {
        when(repo.findByProjectId(projectId)).thenReturn(List.of(new MobileAnalysis()));
        List<MobileAnalysis> result = service.list(projectId);
        assertThat(result).hasSize(1);
    }

    @Test
    void list_withoutProjectId() {
        when(repo.findAll()).thenReturn(List.of(new MobileAnalysis(), new MobileAnalysis()));
        List<MobileAnalysis> result = service.list(null);
        assertThat(result).hasSize(2);
    }

    @Test
    void list_emptyByProject() {
        when(repo.findByProjectId(projectId)).thenReturn(List.of());
        List<MobileAnalysis> result = service.list(projectId);
        assertThat(result).isEmpty();
    }

    // --- get ---

    @Test
    void get_found() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder().fileName("app.apk").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }

    // --- workspace ---

    @Test
    void workspace_returnsExpectedKeys() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("app.apk").platform("ANDROID").fileSha256("abc123").fileSize(1024L)
                .masvsScore(85).manifestJson("{}").stringsJson("[\"http://api.example.com\"]")
                .certInfo("cert info").findingsJson("[]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        assertThat(ws).containsKeys("overview", "manifest", "strings", "certificates", "masvs", "callGraph", "endpoints", "findings");
        assertThat(((Map<?, ?>) ws.get("overview")).get("fileName")).isEqualTo("app.apk");
        assertThat(((Map<?, ?>) ws.get("overview")).get("platform")).isEqualTo("ANDROID");
        assertThat(((Map<?, ?>) ws.get("overview")).get("sha256")).isEqualTo("abc123");
        assertThat(((Map<?, ?>) ws.get("overview")).get("score")).isEqualTo(85);
        assertThat(((Map<?, ?>) ws.get("overview")).get("size")).isEqualTo(1024L);
    }

    @Test
    void workspace_withCleartextInFindings() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("app.apk").platform("ANDROID").fileSha256("abc").fileSize(0L)
                .masvsScore(50).manifestJson("{}").stringsJson("[]").certInfo("")
                .findingsJson("[{\"severity\":\"MEDIUM\",\"title\":\"Cleartext traffic allowed\"}]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        assertThat(ws).containsKey("masvs");
        List<?> masvs = (List<?>) ws.get("masvs");
        assertThat(masvs).isNotEmpty();
    }

    @Test
    void workspace_withNoEndpoints() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("app.apk").platform("ANDROID").fileSha256("abc").fileSize(0L)
                .masvsScore(100).manifestJson("{}").stringsJson("[]").certInfo("")
                .findingsJson("[]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        List<?> endpoints = (List<?>) ws.get("endpoints");
        assertThat(endpoints).isNotEmpty();
        assertThat(endpoints.get(0).toString()).contains("No endpoints");
    }

    @Test
    void workspace_withStorageInFindings_failsMstgStorage() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("app.apk").platform("ANDROID").fileSha256("abc").fileSize(0L)
                .masvsScore(70).manifestJson("{}").stringsJson("[]").certInfo("")
                .findingsJson("[{\"id\":\"MSTG-STORAGE-14\",\"severity\":\"HIGH\"}]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        List<?> masvs = (List<?>) ws.get("masvs");
        assertThat(masvs).isNotEmpty();
    }

    @Test
    void workspace_withHttpEndpoints_filtersCorrectly() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("app.apk").platform("ANDROID").fileSha256("abc").fileSize(0L)
                .masvsScore(100).manifestJson("{}")
                .stringsJson("[\"http://api.example.com\",\"ftp://files.example.com\",\"just-some-text\"]")
                .certInfo("").findingsJson("[]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        List<?> endpoints = (List<?>) ws.get("endpoints");
        assertThat(endpoints).isNotEmpty();
    }

    // --- sha256 ---

    @Test
    void sha256_returnsConsistentHash() {
        byte[] data = "test data".getBytes();
        MockMultipartFile f1 = new MockMultipartFile("file", "a.apk", "application/octet-stream", data);
        MockMultipartFile f2 = new MockMultipartFile("file", "b.apk", "application/octet-stream", data);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis r1 = service.upload(projectId, "a.apk", "ANDROID", f1);
        MobileAnalysis r2 = service.upload(projectId, "b.apk", "ANDROID", f2);
        assertThat(r1.getFileSha256()).isEqualTo(r2.getFileSha256());
    }

    @Test
    void sha256_differentContent_differentHash() throws IOException {
        MockMultipartFile f1 = new MockMultipartFile("file", "a.apk", "application/octet-stream", "content1".getBytes());
        MockMultipartFile f2 = new MockMultipartFile("file", "b.apk", "application/octet-stream", "content2".getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis r1 = service.upload(projectId, "a.apk", "ANDROID", f1);
        MobileAnalysis r2 = service.upload(projectId, "b.apk", "ANDROID", f2);
        assertThat(r1.getFileSha256()).isNotEqualTo(r2.getFileSha256());
    }

    @Test
    void sha256_emptyBytes() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "empty.apk", "ANDROID", null);
        assertThat(result.getFileSha256()).hasSize(64);
    }

    @Test
    void upload_massvsScore_clampsBetween0And100() throws IOException {
        String payload = "CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL CRITICAL";
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", payload.getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getMasvsScore()).isGreaterThanOrEqualTo(0);
        assertThat(result.getMasvsScore()).isLessThanOrEqualTo(100);
    }

    @Test
    void upload_certInfo_containsEntriesCount() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "app.apk", "application/octet-stream", "PKdata".getBytes());
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        MobileAnalysis result = service.upload(projectId, "app.apk", "ANDROID", file);
        assertThat(result.getCertInfo()).contains("entries:");
    }

    @Test
    void workspace_overview_hasAllFields() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .fileName("test.apk").platform("IOS").fileSha256("def456").fileSize(2048L)
                .masvsScore(90).manifestJson("{\"package\":\"com.test\"}")
                .stringsJson("[]").certInfo("cert").findingsJson("[]").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ma));
        Map<String, Object> ws = service.workspace(id);
        assertThat(ws.get("manifest")).isEqualTo("{\"package\":\"com.test\"}");
        assertThat(ws.get("certificates")).isEqualTo("cert");
        assertThat(ws.get("findings")).isEqualTo("[]");
        assertThat(ws.get("callGraph")).isNotNull();
    }
}
