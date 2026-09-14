package com.vulnerax.modules.k8s;

import com.vulnerax.common.exception.BusinessException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class K8sServiceTest {

    @Mock K8sRepository repo;
    @InjectMocks K8sService service;

    @Test
    void create_setsDefaultRiskJson() {
        K8sResource k = K8sResource.builder()
                .projectId(UUID.randomUUID()).clusterName("prod-cluster")
                .kind("Deployment").name("api-server").build();
        when(repo.save(any())).thenAnswer(i -> {
            K8sResource arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.create(k);
        assertThat(result.getId()).isNotNull();
        assertThat(k.getRiskJson()).contains("ClusterAdmin");
        assertThat(k.getRiskJson()).contains("privileged");
        verify(repo).save(k);
    }

    @Test
    void create_preservesExistingRiskJson() {
        K8sResource k = K8sResource.builder()
                .projectId(UUID.randomUUID()).clusterName("dev-cluster")
                .kind("Service").name("web-svc")
                .riskJson("{\"custom\":\"risk\"}").build();
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        service.create(k);
        assertThat(k.getRiskJson()).isEqualTo("{\"custom\":\"risk\"}");
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                K8sResource.builder().projectId(pid).clusterName("prod").kind("Deployment").name("api").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                K8sResource.builder().clusterName("prod").kind("Deployment").name("api").build(),
                K8sResource.builder().clusterName("staging").kind("Service").name("web").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        K8sResource k = K8sResource.builder().clusterName("prod").kind("Deployment").name("api").build();
        k.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(k));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void scanMock_throwsBusinessException() {
        assertThatThrownBy(() -> service.scanMock(UUID.randomUUID()))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("Real K8s discovery required");
    }
}
