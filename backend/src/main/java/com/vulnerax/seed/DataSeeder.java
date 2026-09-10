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
        log.info("Seeding VulneraX demo data...");

        // Users
        User admin = userRepo.save(User.builder().email("admin@vulnerax.io").passwordHash(encoder.encode("Admin123!")).fullName("Security Admin").role(User.Role.ORG_OWNER).build());
        User sec = userRepo.save(User.builder().email("sec@vulnerax.io").passwordHash(encoder.encode("Sec123!")).fullName("Alice Sec").role(User.Role.SECURITY_ENGINEER).build());
        User dev = userRepo.save(User.builder().email("dev@vulnerax.io").passwordHash(encoder.encode("Dev123!")).fullName("Bob Dev").role(User.Role.DEVELOPER).build());

        // Org -> Workspace -> Project
        Organization org = orgRepo.save(Organization.builder().name("Acme Financial").slug("acme-financial").description("Demo enterprise org").tier("ENTERPRISE").build());
        Workspace ws = wsRepo.save(Workspace.builder().name("Primary Workspace").organizationId(org.getId()).description("Main").environment("PRODUCTION").build());
        Project proj = projRepo.save(Project.builder().name("Digital Banking").workspaceId(ws.getId()).organizationId(org.getId()).description("Mobile + API banking platform").criticality("CRITICAL").businessUnit("Retail Banking").techLead("Bob Dev").securityChampion("Alice Sec").build());
        Project proj2 = projRepo.save(Project.builder().name("Payment Gateway").workspaceId(ws.getId()).organizationId(org.getId()).description("Payment microservices").criticality("CRITICAL").build());

        // Assets
        Asset api = assetRepo.save(Asset.builder().projectId(proj.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("Payment API").type("API").identifier("api.acme.com/v1/pay").internetExposed(true).criticality("CRITICAL").technology("Spring Boot").owner("Platform Team").environment("PRODUCTION").build());
        assetRepo.save(Asset.builder().projectId(proj.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("Android Banking App").type("MOBILE_APP").identifier("com.acme.bank v2.4.1").criticality("CRITICAL").technology("Kotlin").owner("Mobile Team").build());
        assetRepo.save(Asset.builder().projectId(proj.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("PostgreSQL - Transactions").type("DATABASE").identifier("pg-transactions.internal:5432").criticality("CRITICAL").technology("PostgreSQL 15").build());
        assetRepo.save(Asset.builder().projectId(proj.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("Web Frontend").type("WEBAPP").identifier("bank.acme.com").internetExposed(true).criticality("HIGH").technology("React").build());
        assetRepo.save(Asset.builder().projectId(proj2.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("K8s Cluster Prod").type("K8S_CLUSTER").identifier("k8s-prod-01").criticality("HIGH").technology("EKS 1.28").build());
        Asset repoAsset = assetRepo.save(Asset.builder().projectId(proj.getId()).organizationId(org.getId()).workspaceId(ws.getId()).name("payment-service").type("REPOSITORY").identifier("github.com/acme/payment-service").criticality("CRITICAL").technology("Java 17").owner("Platform Team").build());

        // Findings (with risk enrichment)
        findingService.create(Finding.builder().title("Broken Object Level Authorization on /accounts/{id}").description("BOLA allows accessing other users accounts").type("AUTHORIZATION").severity("CRITICAL").confidence("CONFIRMED").status("OPEN").projectId(proj.getId()).assetId(api.getId()).assetName(api.getName()).environment("PRODUCTION").source("api-security-engine").cwe("CWE-639").owasp("API1:2023").cvss(8.1).epss(0.72).kev(false).internetExposed(true).reachable(true).businessCriticality("CRITICAL").owner("Platform Team").filePath("src/main/java/com/acme/payment/AccountService.java").lineNumber(87).functionName("getAccount").dataFlow("request param id -> service -> repo without ownership check").recommendation("Validate ownership: check account.ownerId == currentUser.id before repository access.").build());
        findingService.create(Finding.builder().title("SQL Injection via search param").description("Unsanitized input concatenated into SQL").type("INJECTION").severity("HIGH").confidence("HIGH").status("OPEN").projectId(proj.getId()).assetId(api.getId()).assetName(api.getName()).environment("PRODUCTION").source("sast-engine").cwe("CWE-89").owasp("A03:2021").cvss(9.8).epss(0.85).kev(true).internetExposed(true).reachable(true).businessCriticality("CRITICAL").owner("Platform Team").filePath("src/main/java/com/acme/payment/SearchController.java").lineNumber(42).codeSnippet("String q = \"SELECT * FROM tx WHERE id=\" + input;").build());
        findingService.create(Finding.builder().title("Hardcoded AWS Secret in Android APK").description("AKIA key found in strings.xml").type("SECRET").severity("HIGH").confidence("HIGH").status("OPEN").projectId(proj.getId()).assetId(api.getId()).assetName("Android Banking App").environment("PRODUCTION").source("secret-engine").cwe("CWE-798").cvss(7.5).epss(0.3).businessCriticality("CRITICAL").owner("Mobile Team").build());
        findingService.create(Finding.builder().title("Vulnerable Dependency: log4j 2.14.1 (CVE-2021-44228)").description("Log4Shell remote code execution").type("SCA").severity("CRITICAL").confidence("HIGH").status("OPEN").projectId(proj.getId()).assetId(repoAsset.getId()).assetName(repoAsset.getName()).environment("PRODUCTION").source("sca-engine").cwe("CWE-1104").cvss(10.0).epss(0.96).kev(true).reachable(true).businessCriticality("CRITICAL").build());
        findingService.create(Finding.builder().title("Container Running as Root").description("Payment service Dockerfile USER not set").type("CONTAINER").severity("MEDIUM").confidence("MEDIUM").status("OPEN").projectId(proj2.getId()).assetId(api.getId()).assetName("payment-service image").source("container-engine").cwe("CWE-250").cvss(5.5).businessCriticality("HIGH").build());

        log.info("Seed done: admin@vulnerax.io / Admin123!");
    }
}
