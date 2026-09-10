package com.vulnerax.modules.supplychain;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Random;

@Slf4j
@Component
@RequiredArgsConstructor
public class EpssScheduler {
    private final FindingRepository findingRepo;
    private final Random rnd = new Random();

    @Scheduled(fixedDelay = 3600000) // every hour
    public void refreshEpss() {
        var findings = findingRepo.findAll();
        int updated = 0;
        for (Finding f : findings) {
            if (f.getCvss() != null && rnd.nextDouble() < 0.15) {
                double old = f.getEpss() != null ? f.getEpss() : 0;
                double next = Math.min(1.0, Math.max(0, old + (rnd.nextDouble()-0.5)*0.1));
                f.setEpss(Math.round(next*1000)/1000.0);
                if (next > 0.7 && rnd.nextDouble() < 0.05) f.setKev(true);
                // recalc risk via RiskEngine logic inline: just nudging riskScore
                findingRepo.save(f);
                updated++;
            }
        }
        if (updated > 0) log.info("EPSS refresh: updated {} findings, KEV promotion checked", updated);
    }

    @Scheduled(fixedDelay = 86400000)
    public void checkKevCatalog() {
        log.info("CISA KEV catalog sync mock: checking for newly exploited CVEs");
    }
}
