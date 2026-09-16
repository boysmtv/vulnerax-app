package com.vulnerax.seed;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.User;
import com.vulnerax.modules.identity.UserRepository;
import com.vulnerax.modules.organization.Organization;
import com.vulnerax.modules.organization.OrganizationRepository;
import com.vulnerax.modules.organization.Project;
import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.organization.Workspace;
import com.vulnerax.modules.organization.WorkspaceRepository;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Profile("!test")
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {
    private final UserRepository userRepo;
    private final OrganizationRepository orgRepo;
    private final WorkspaceRepository wsRepo;
    private final ProjectRepository projRepo;
    private final AssetRepository assetRepo;
    private final FindingService findingService;
    private final PasswordEncoder encoder;

    @Override
    public void run(String... args) {
        if (userRepo.count() > 0) return;
        log.info("Seeding minimal bootstrap (no mock assets/findings) — real data via onboarding & scans");

        // Only bootstrap admin user if none exists; org/projects/assets/findings must be created via real onboarding/API/scans
        // Controlled by env VULNERAX_SEED_DEMO=false (default). Demo mock disabled per request "hilangkan semua data mock".
        String demo = System.getenv("VULNERAX_SEED_DEMO");
        if ("true".equalsIgnoreCase(demo)) {
            log.warn("VULNERAX_SEED_DEMO=true — demo seed skipped (mock removed)");
        }
        User admin = userRepo.save(User.builder().email("admin@vulnerax.io").passwordHash(encoder.encode("Admin12345!abc")).fullName("Security Admin").role(User.Role.ORG_OWNER).build());
        // No mock org/workspace/project/asset/finding — must be created via POST /api/v1/organizations /projects /assets and real scans
        log.info("Seed done: admin@vulnerax.io / Admin12345!abc (no mock data)");
    }
}
