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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SlaBreachSchedulerTest {

    @Mock
    FindingRepository findingRepo;

    @InjectMocks
    SlaBreachScheduler scheduler;

    private Finding buildFinding(String severity, int daysOverdue) {
        Finding f = new Finding();
        f.setFindingId("FINDING-001");
        f.setTitle("Test Finding");
        f.setSeverity(severity);
        f.setStatus("OPEN");
        f.setSlaDueAt(Instant.now().minus(daysOverdue, ChronoUnit.DAYS));
        return f;
    }

    @Test
    void checkSlaBreaches_noBreachedFindings_doesNothing() {
        when(findingRepo.findSlaBreached()).thenReturn(List.of());

        scheduler.checkSlaBreaches();

        verify(findingRepo, never()).save(any());
    }

    @Test
    void checkSlaBreaches_breachedFinding_marksAsBreached() {
        Finding f = buildFinding("HIGH", 3);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("BREACHED", f.getSlaStatus());
        verify(findingRepo).save(f);
    }

    @Test
    void checkSlaBreaches_highOverdue7Days_escalatesToCritical() {
        Finding f = buildFinding("HIGH", 10);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("CRITICAL", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_highOverdueLessThan7Days_noEscalation() {
        Finding f = buildFinding("HIGH", 5);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("HIGH", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_mediumOverdue30Days_escalatesToHigh() {
        Finding f = buildFinding("MEDIUM", 35);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("HIGH", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_mediumOverdueLessThan30Days_noEscalation() {
        Finding f = buildFinding("MEDIUM", 20);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("MEDIUM", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_criticalSeverity_noEscalation() {
        Finding f = buildFinding("CRITICAL", 15);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("CRITICAL", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_lowSeverity_noEscalation() {
        Finding f = buildFinding("LOW", 60);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("LOW", f.getSeverity());
        assertEquals("BREACHED", f.getSlaStatus());
    }

    @Test
    void checkSlaBreaches_multipleFindings_allSaved() {
        Finding f1 = buildFinding("HIGH", 10);
        Finding f2 = buildFinding("MEDIUM", 35);
        Finding f3 = buildFinding("LOW", 5);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f1, f2, f3));

        scheduler.checkSlaBreaches();

        verify(findingRepo, times(3)).save(any());
        assertEquals("CRITICAL", f1.getSeverity());
        assertEquals("HIGH", f2.getSeverity());
        assertEquals("LOW", f3.getSeverity());
    }

    @Test
    void checkSlaBreaches_highOverdueExactly7Days_noEscalation() {
        Finding f = buildFinding("HIGH", 7);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("HIGH", f.getSeverity());
    }

    @Test
    void checkSlaBreaches_mediumOverdueExactly30Days_noEscalation() {
        Finding f = buildFinding("MEDIUM", 30);
        when(findingRepo.findSlaBreached()).thenReturn(List.of(f));

        scheduler.checkSlaBreaches();

        assertEquals("MEDIUM", f.getSeverity());
    }

    @Test
    void weeklySlaReport_noBreachedFindings_doesNothing() {
        when(findingRepo.countSlaBreached()).thenReturn(0L);

        scheduler.weeklySlaReport();

        verify(findingRepo).countSlaBreached();
    }

    @Test
    void weeklySlaReport_hasBreachedFindings_logsWarning() {
        when(findingRepo.countSlaBreached()).thenReturn(5L);

        scheduler.weeklySlaReport();

        verify(findingRepo).countSlaBreached();
    }
}
