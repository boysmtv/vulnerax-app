package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FindingControllerUnitTest {

    @Mock FindingService service;
    @InjectMocks FindingController controller;

    @Test
    void list_delegates() {
        Finding f = Finding.builder().findingId("FND-1").title("XSS").severity("HIGH").build();
        when(service.list(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new PageImpl<>(List.of(f)));
        var res = controller.list(UUID.randomUUID(), null, "HIGH", "OPEN", null, "xss", PageRequest.of(0, 20));
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void get_create_evidences_instances_stats_correlation() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("FND-1").title("XSS").severity("HIGH").build();
        when(service.get(id)).thenReturn(f);
        assertThat(controller.get(id).isSuccess()).isTrue();
        when(service.create(any())).thenReturn(f);
        assertThat(controller.create(f).isSuccess()).isTrue();
        when(service.evidences(id)).thenReturn(List.of());
        assertThat(controller.evidences(id).isSuccess()).isTrue();
        when(service.instances(id)).thenReturn(List.of());
        assertThat(controller.instances(id).isSuccess()).isTrue();
        when(service.stats(any())).thenReturn(Map.of("total", 1));
        assertThat(controller.stats(UUID.randomUUID()).isSuccess()).isTrue();
        when(service.correlation(id)).thenReturn(Map.of("count", 0));
        assertThat(controller.correlation(id).isSuccess()).isTrue();
    }

    @Test
    void updateStatus_delegates() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("FND-1").title("XSS").severity("HIGH").build();
        FindingController.StatusReq req = new FindingController.StatusReq();
        req.setStatus("RESOLVED"); req.setComment("fixed");
        when(service.updateStatus(id, "RESOLVED", "fixed")).thenReturn(f);
        var res = controller.updateStatus(id, req);
        assertThat(res.isSuccess()).isTrue();
        assertThat(req.toString()).contains("RESOLVED");
    }

    @Test
    void statusReq_equals() {
        FindingController.StatusReq a = new FindingController.StatusReq();
        a.setStatus("OPEN"); a.setComment("c");
        FindingController.StatusReq b = new FindingController.StatusReq();
        b.setStatus("OPEN"); b.setComment("c");
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("x");
        b.setStatus("CLOSED");
        assertThat(a).isNotEqualTo(b);
    }
}
