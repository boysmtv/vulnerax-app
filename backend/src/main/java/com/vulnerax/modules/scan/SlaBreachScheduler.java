package com.vulnerax.modules.scan;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.identity.TenantContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class SlaBreachScheduler {

    private final FindingRepository findingRepo;

    @Scheduled(fixedRate = 300000) // every 5 minutes
    @Transactional
    public void checkSlaBreaches() {
        List<Finding> breached = findingRepo.findSlaBreached();
        if (breached.isEmpty()) return;

        log.info("SLA breach check: {} findings breached SLA", breached.size());

        for (Finding f : breached) {
            f.setSlaStatus("BREACHED");

            // Auto-escalate severity for CRITICAL/HIGH that are overdue
            long daysOverdue = ChronoUnit.DAYS.between(f.getSlaDueAt(), Instant.now());
            if (daysOverdue > 7 && "HIGH".equals(f.getSeverity())) {
                f.setSeverity("CRITICAL");
                log.warn("SLA escalation: {} overdue {} days, severity -> CRITICAL", f.getFindingId(), daysOverdue);
            } else if (daysOverdue > 30 && "MEDIUM".equals(f.getSeverity())) {
                f.setSeverity("HIGH");
                log.warn("SLA escalation: {} overdue {} days, severity -> HIGH", f.getFindingId(), daysOverdue);
            }

            findingRepo.save(f);
        }

        log.info("SLA breach update completed: {} findings marked BREACHED", breached.size());
    }

    @Scheduled(cron = "0 0 8 * * MON") // Every Monday 8 AM
    @Transactional
    public void weeklySlaReport() {
        long totalBreached = findingRepo.countSlaBreached();
        if (totalBreached > 0) {
            log.warn("WEEKLY SLA REPORT: {} findings with breached SLAs need attention", totalBreached);
        }
    }
}
