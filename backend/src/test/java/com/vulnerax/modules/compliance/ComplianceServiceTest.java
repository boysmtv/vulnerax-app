package com.vulnerax.modules.compliance;

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
class ComplianceServiceTest {

    @Mock ComplianceFrameworkRepository fwRepo;
    @Mock ComplianceAssessmentRepository asRepo;
    @InjectMocks ComplianceService service;

    // frameworks
    @Test
    void frameworks_returnsList() {
        when(fwRepo.findAll()).thenReturn(List.of(
                ComplianceFramework.builder().name("OWASP").version("4.0").build(),
                ComplianceFramework.builder().name("NIST").version("2.0").build()
        ));
        var list = service.frameworks();
        assertThat(list).hasSize(2);
        verify(fwRepo).findAll();
    }

    @Test
    void frameworks_emptyList() {
        when(fwRepo.findAll()).thenReturn(List.of());
        var list = service.frameworks();
        assertThat(list).isEmpty();
    }

    // getFramework
    @Test
    void getFramework_found() {
        UUID id = UUID.randomUUID();
        ComplianceFramework fw = ComplianceFramework.builder().name("CIS").version("8.1").build();
        fw.setId(id);
        when(fwRepo.findById(id)).thenReturn(Optional.of(fw));
        assertThat(service.getFramework(id).getName()).isEqualTo("CIS");
    }

    @Test
    void getFramework_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(fwRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.getFramework(id))
                .isInstanceOf(NoSuchElementException.class);
    }

    // assess
    @Test
    void assess_savesAndReturnsAssessment() {
        UUID projectId = UUID.randomUUID();
        UUID frameworkId = UUID.randomUUID();
        ComplianceAssessment saved = ComplianceAssessment.builder()
                .projectId(projectId).frameworkId(frameworkId)
                .passed(200).failed(25).notApplicable(15).notTested(46)
                .score(71.0).status("COMPLETED").build();
        when(asRepo.save(any())).thenReturn(saved);
        var result = service.assess(projectId, frameworkId);
        assertThat(result.getProjectId()).isEqualTo(projectId);
        assertThat(result.getFrameworkId()).isEqualTo(frameworkId);
        assertThat(result.getStatus()).isEqualTo("COMPLETED");
        assertThat(result.getScore()).isGreaterThan(0);
        verify(asRepo).save(any());
    }

    @Test
    void assess_passesCorrectFields() {
        UUID pid = UUID.randomUUID();
        UUID fid = UUID.randomUUID();
        when(asRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        var result = service.assess(pid, fid);
        assertThat(result.getPassed()).isGreaterThan(0);
        assertThat(result.getFailed()).isGreaterThan(0);
        assertThat(result.getNotApplicable()).isEqualTo(15);
        assertThat(result.getNotTested()).isGreaterThanOrEqualTo(0);
        assertThat(result.getResultsJson()).contains("1.1.1");
    }

    // list
    @Test
    void list_withProjectId_filtersByProject() {
        UUID pid = UUID.randomUUID();
        when(asRepo.findByProjectId(pid)).thenReturn(List.of(
                ComplianceAssessment.builder().projectId(pid).build()
        ));
        var list = service.list(pid);
        assertThat(list).hasSize(1);
        verify(asRepo).findByProjectId(pid);
        verify(asRepo, never()).findAll();
    }

    @Test
    void list_nullProjectId_returnsAll() {
        when(asRepo.findAll()).thenReturn(List.of());
        var list = service.list(null);
        assertThat(list).isEmpty();
        verify(asRepo).findAll();
        verify(asRepo, never()).findByProjectId(any());
    }

    // get
    @Test
    void get_found() {
        UUID id = UUID.randomUUID();
        ComplianceAssessment a = ComplianceAssessment.builder().projectId(UUID.randomUUID()).build();
        a.setId(id);
        when(asRepo.findById(id)).thenReturn(Optional.of(a));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(asRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
