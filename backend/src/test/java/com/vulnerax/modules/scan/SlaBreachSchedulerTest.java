package com.vulnerax.modules.scan;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SlaBreachSchedulerTest {

    @Mock FindingRepository findingRepo;
    @InjectMocks SlaBreachScheduler scheduler;

    @Test
    void check_empty_noAction() {
        when(findingRepo.findSlaBreached()).thenReturn(List.of());
        scheduler.checkSlaBreaches();
        verify(findingRepo, never()).save(any());
    }

    @Test
    void check_highOverdue8Days_escalatesToCritical() {
        Finding f = new Finding();
        f.setFindingId("FND-1");
        f.setSeverity("HIGH");
        f.setSlaDueAt(Instant.now().minus(8, ChronoUnit.DAYS));
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));
        scheduler.checkSlaBreaches();
        assertThat(f.getSlaStatus()).isEqualTo("BREACHED");
        assertThat(f.getSeverity()).isEqualTo("CRITICAL");
        verify(findingRepo).save(f);
    }

    @Test
    void check_mediumOverdue31Days_escalatesToHigh() {
        Finding f = new Finding();
        f.setFindingId("FND-2");
        f.setSeverity("MEDIUM");
        f.setSlaDueAt(Instant.now().minus(31, ChronoUnit.DAYS));
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));
        scheduler.checkSlaBreaches();
        assertThat(f.getSeverity()).isEqualTo("HIGH");
        verify(findingRepo).save(f);
    }

    @Test
    void check_recentBreach_noEscalation() {
        Finding f = new Finding();
        f.setFindingId("FND-3");
        f.setSeverity("LOW");
        f.setSlaDueAt(Instant.now().minus(2, ChronoUnit.DAYS));
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));
        scheduler.checkSlaBreaches();
        assertThat(f.getSlaStatus()).isEqualTo("BREACHED");
        assertThat(f.getSeverity()).isEqualTo("LOW");
    }

    @Test
    void check_highNotOverdueEnough_noEscalation() {
        Finding f = new Finding();
        f.setFindingId("FND-4");
        f.setSeverity("HIGH");
        f.setSlaDueAt(Instant.now().minus(3, ChronoUnit.DAYS));
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));
        scheduler.checkSlaBreaches();
        assertThat(f.getSeverity()).isEqualTo("HIGH");
    }

    @Test
    void weeklyReport_zero_noWarn() {
        when(findingRepo.countSlaBreached()).thenReturn(0L);
        scheduler.weeklySlaReport();
        verify(findingRepo).countSlaBreached();
    }

    @Test
    void weeklyReport_positive_logs() {
        when(findingRepo.countSlaBreached()).thenReturn(5L);
        scheduler.weeklySlaReport();
        verify(findingRepo).countSlaBreached();
    }
}
