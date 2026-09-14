package com.vulnerax.modules.assessment;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AssessmentControllerServiceTest {

    @Mock AssetRepository assetRepo;
    @Mock ScanService scanService;
    @InjectMocks AssessmentController controller;

    @Test
    void runProjectAssessment_emptyAssets_returnsFail() {
        UUID projectId = UUID.randomUUID();
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        assertNotNull(result);
        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertTrue(result.getMessage().contains("No assets"));
    }

    @Test
    void runProjectAssessment_withRepositoryAsset_creates3Scans() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("Backend Repo");
        asset.setType("REPOSITORY");
        asset.setIdentifier("github.com/acme/backend");
        asset.setTechnology("Java");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(3, data.get("scansCreated"));
        verify(scanService, times(3)).create(any(Scan.class), eq("assessment-orchestrator"));
    }

    @Test
    void runProjectAssessment_withMobileAsset_creates2Scans() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("Android App");
        asset.setType("MOBILE_APP");
        asset.setIdentifier("com.acme.app");
        asset.setTechnology("Kotlin");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(2, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_withApiAsset_creates3Scans() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("API Gateway");
        asset.setType("API");
        asset.setIdentifier("https://api.acme.com");
        asset.setTechnology("REST");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(3, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_withWebappAsset_creates1Scan() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("Web App");
        asset.setType("WEBAPP");
        asset.setIdentifier("https://app.acme.com");
        asset.setTechnology("React");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(1, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_withContainerAsset_creates1Scan() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("Docker Image");
        asset.setType("CONTAINER_IMAGE");
        asset.setIdentifier("nginx:latest");
        asset.setTechnology("Docker");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(1, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_withK8sAsset_creates1Scan() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("K8s Cluster");
        asset.setType("K8S_CLUSTER");
        asset.setIdentifier("production-cluster");
        asset.setTechnology("Kubernetes");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(1, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_withDatabaseAsset_creates1Scan() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("PostgreSQL");
        asset.setType("DATABASE");
        asset.setIdentifier("db.acme.com:5432");
        asset.setTechnology("PostgreSQL");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(1, data.get("scansCreated"));
    }

    @Test
    void runProjectAssessment_defaultProfile_usesStandard() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setId(UUID.randomUUID());
        asset.setName("Web App");
        asset.setType("WEBAPP");
        asset.setIdentifier("https://example.com");
        asset.setTechnology("React");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        verify(scanService).create(argThat(s -> "STANDARD".equals(s.getProfile())), eq("assessment-orchestrator"));
    }

    @Test
    void runProjectAssessment_multipleAssets_aggregatesScans() {
        UUID projectId = UUID.randomUUID();
        Asset a1 = new Asset();
        a1.setId(UUID.randomUUID());
        a1.setName("Repo");
        a1.setType("REPOSITORY");
        a1.setIdentifier("github.com/acme/repo");
        a1.setTechnology("Java");
        Asset a2 = new Asset();
        a2.setId(UUID.randomUUID());
        a2.setName("API");
        a2.setType("API");
        a2.setIdentifier("https://api.acme.com");
        a2.setTechnology("REST");
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(a1, a2));
        when(scanService.create(any(Scan.class), eq("assessment-orchestrator")))
                .thenAnswer(inv -> {
                    Scan s = new Scan();
                    s.setId(UUID.randomUUID());
                    return s;
                });

        var result = controller.runProjectAssessment(projectId, "STANDARD");

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(2, data.get("assets"));
        int scansCreated = (int) data.get("scansCreated");
        assertTrue(scansCreated >= 4);
    }

    @Test
    void summary_withAssets_returnsAll() {
        UUID projectId = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setName("Web App");
        asset.setType("WEBAPP");
        asset.setTechnology("React");
        asset.setInternetExposed(true);
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(asset));

        var result = controller.summary(projectId);

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(1, data.get("totalAssets"));
    }

    @Test
    void summary_emptyAssets_returnsZero() {
        UUID projectId = UUID.randomUUID();
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());

        var result = controller.summary(projectId);

        Map<?, ?> data = (Map<?, ?>) result.getData();
        assertEquals(0, data.get("totalAssets"));
    }
}
