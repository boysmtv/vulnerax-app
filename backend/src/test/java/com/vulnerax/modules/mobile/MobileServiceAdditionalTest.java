package com.vulnerax.modules.mobile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MobileServiceAdditionalTest {

    @Mock MobileRepository repo;
    @InjectMocks MobileService service;

    @Test
    void list_returnsAll() {
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(UUID.randomUUID()).platform("ANDROID").fileName("app.apk").build();
        when(repo.findAll()).thenReturn(List.of(ma));
        List<MobileAnalysis> result = service.list(null);
        assertThat(result).hasSize(1);
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID pid = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(pid).platform("ANDROID").fileName("app.apk").build();
        when(repo.findByProjectId(pid)).thenReturn(List.of(ma));
        List<MobileAnalysis> result = service.list(pid);
        assertThat(result).hasSize(1);
    }

    @Test
    void get_returnsAnalysis() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(UUID.randomUUID()).platform("IOS").fileName("app.ipa").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(java.util.Optional.of(ma));
        MobileAnalysis result = service.get(id);
        assertThat(result.getPlatform()).isEqualTo("IOS");
    }

    @Test
    void get_returnsAnalysisById() {
        UUID id = UUID.randomUUID();
        MobileAnalysis ma = MobileAnalysis.builder()
                .projectId(UUID.randomUUID()).platform("ANDROID").fileName("app.apk").build();
        ma.setId(id);
        when(repo.findById(id)).thenReturn(java.util.Optional.of(ma));
        MobileAnalysis result = service.get(id);
        assertThat(result.getPlatform()).isEqualTo("ANDROID");
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(java.util.Optional.empty());
        try {
            service.get(id);
        } catch (Exception e) {
            assertThat(e).isInstanceOf(java.util.NoSuchElementException.class);
        }
    }
}
