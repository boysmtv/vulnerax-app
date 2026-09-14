package com.vulnerax.modules.threatmodel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ThreatModelServiceTest {

    @Mock ThreatModelRepository repo;
    @InjectMocks ThreatModelService service;

    // create
    @Test
    void create_savesAndReturnsModel() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("Payment System").build();
        ThreatModel saved = ThreatModel.builder().projectId(m.getProjectId()).name("Payment System").build();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);
        var result = service.create(m);
        assertThat(result.getId()).isNotNull();
        verify(repo).save(m);
    }

    @Test
    void create_nullComponents_setsDefault() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM1")
                .componentsJson(null).build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getComponentsJson()).contains("Web Frontend");
        assertThat(m.getComponentsJson()).contains("API Gateway");
        assertThat(m.getComponentsJson()).contains("PostgreSQL");
    }

    @Test
    void create_nullDataflows_setsDefault() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM2")
                .dataflowsJson(null).build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getDataflowsJson()).contains("HTTPS JSON");
        assertThat(m.getDataflowsJson()).contains("SQL");
    }

    @Test
    void create_nullTrustBoundaries_setsDefault() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM3")
                .trustBoundariesJson(null).build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getTrustBoundariesJson()).contains("Internet");
    }

    @Test
    void create_nullThreats_generatesSTRIDE() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM4")
                .threatsJson(null).build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getThreatsJson()).contains("STRIDE-S");
        assertThat(m.getThreatsJson()).contains("STRIDE-T");
        assertThat(m.getThreatsJson()).contains("STRIDE-R");
        assertThat(m.getThreatsJson()).contains("STRIDE-I");
        assertThat(m.getThreatsJson()).contains("STRIDE-D");
        assertThat(m.getThreatsJson()).contains("STRIDE-E");
        assertThat(m.getThreatsJson()).contains("Spoofing");
        assertThat(m.getThreatsJson()).contains("Tampering");
        assertThat(m.getThreatsJson()).contains("Repudiation");
        assertThat(m.getThreatsJson()).contains("Information Disclosure");
        assertThat(m.getThreatsJson()).contains("DoS");
        assertThat(m.getThreatsJson()).contains("Elevation");
    }

    @Test
    void create_nullControls_setsDefault() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM5")
                .controlsJson(null).build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getControlsJson()).contains("OAuth2 OIDC");
        assertThat(m.getControlsJson()).contains("WAF");
    }

    @Test
    void create_existingFields_notOverwritten() {
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("TM6")
                .componentsJson("[{\"custom\":true}]")
                .dataflowsJson("[{\"custom\":true}]")
                .trustBoundariesJson("[{\"custom\":true}]")
                .threatsJson("[{\"custom\":true}]")
                .controlsJson("[{\"custom\":true}]")
                .build();
        when(repo.save(any())).thenAnswer(i -> {
            ThreatModel arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(m);
        assertThat(m.getComponentsJson()).contains("custom");
        assertThat(m.getDataflowsJson()).contains("custom");
        assertThat(m.getTrustBoundariesJson()).contains("custom");
        assertThat(m.getThreatsJson()).contains("custom");
        assertThat(m.getControlsJson()).contains("custom");
    }

    // list
    @Test
    void list_withProjectId_filtersByProject() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                ThreatModel.builder().projectId(pid).name("TM1").build()
        ));
        var list = service.list(pid);
        assertThat(list).hasSize(1);
        verify(repo).findByProjectId(pid);
        verify(repo, never()).findAll();
    }

    @Test
    void list_nullProjectId_returnsAll() {
        when(repo.findAll()).thenReturn(List.of());
        var list = service.list(null);
        assertThat(list).isEmpty();
        verify(repo).findAll();
    }

    // get
    @Test
    void get_found() {
        UUID id = UUID.randomUUID();
        ThreatModel m = ThreatModel.builder().projectId(UUID.randomUUID()).name("Payment").build();
        m.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(m));
        assertThat(service.get(id).getName()).isEqualTo("Payment");
    }

    @Test
    void get_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
