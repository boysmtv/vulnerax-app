package com.vulnerax.modules.cloud;

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
class CloudServiceTest {

    @Mock CloudRepository repo;
    @InjectMocks CloudService service;

    @Test
    void create_setsDefaultRiskAndCompliance() {
        CloudResource c = CloudResource.builder()
                .projectId(UUID.randomUUID()).provider("AWS")
                .accountId("123456789").region("us-east-1")
                .service("EC2").resourceType("INSTANCE").resourceId("i-abc123").build();
        when(repo.save(any())).thenAnswer(i -> {
            CloudResource arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.create(c);
        assertThat(result.getId()).isNotNull();
        assertThat(c.getRiskJson()).contains("Least privilege");
        assertThat(c.getComplianceJson()).contains("CIS");
        verify(repo).save(c);
    }

    @Test
    void create_preservesExistingRiskAndCompliance() {
        CloudResource c = CloudResource.builder()
                .projectId(UUID.randomUUID()).provider("AWS")
                .accountId("123456789").region("us-east-1")
                .service("S3").resourceType("BUCKET").resourceId("my-bucket")
                .riskJson("{\"custom\":\"risk\"}").complianceJson("{\"custom\":\"comp\"}").build();
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        service.create(c);
        assertThat(c.getRiskJson()).isEqualTo("{\"custom\":\"risk\"}");
        assertThat(c.getComplianceJson()).isEqualTo("{\"custom\":\"comp\"}");
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                CloudResource.builder().projectId(pid).provider("AWS").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                CloudResource.builder().provider("AWS").build(),
                CloudResource.builder().provider("GCP").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        CloudResource c = CloudResource.builder().provider("AWS").build();
        c.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(c));
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
                .hasMessageContaining("Real cloud discovery required");
    }
}
