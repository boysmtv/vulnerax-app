package com.vulnerax.modules.finding;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity @Table(name = "findings", indexes = {@Index(columnList = "projectId"), @Index(columnList = "severity"), @Index(columnList = "status")})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Finding extends BaseEntity {

    @Column(nullable = false, unique = true) private String findingId; // FND-xxxx

    @Column(nullable = false) private String title;
    @Column(columnDefinition = "TEXT") private String description;
    @Column(nullable = false) private String type; // INJECTION, AUTH, CRYPTO, etc
    @Column(nullable = false) private String severity; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    @Column(nullable = false) private String confidence; // CONFIRMED, HIGH, MEDIUM, LOW, INFO
    @Builder.Default private String status = "OPEN"; // OPEN, TRIAGING, CONFIRMED, ASSIGNED, IN_PROGRESS, FIXED, READY_FOR_RETEST, RETESTING, RESOLVED, RISK_ACCEPTED, FALSE_POSITIVE, DUPLICATE, WONT_FIX, REOPENED

    private UUID projectId;
    private UUID assetId;
    private String assetName;
    private String environment; // PRODUCTION etc

    private String source; // scanner name or MANUAL
    private UUID scanId;

    // Standards mapping
    private String cwe; // e.g. CWE-89
    private String owasp; // e.g. A03:2021 or API1:2023
    private String masvs;
    private String asvs;

    private Double cvss; // CVSS 4.0 base
    private Double epss; // 0-1
    @Builder.Default private Boolean kev = false;
    @Builder.Default private Boolean internetExposed = false;
    @Builder.Default private Boolean reachable = false;
    private String businessCriticality; // CRITICAL etc
    private String owner; // team/user
    private String filePath;
    private Integer lineNumber;
    private String functionName;
    @Column(columnDefinition = "TEXT") private String codeSnippet;
    @Column(columnDefinition = "TEXT") private String dataFlow;
    @Column(columnDefinition = "TEXT") private String recommendation;

    private Double riskScore; // 0-100 contextual
    private String riskLevel; // LOW, MODERATE, HIGH, VERY_HIGH, CRITICAL

    private String fingerprint; // dedup
    @Builder.Default private Boolean falsePositive = false;
    @Builder.Default private Boolean duplicate = false;

    private UUID parentFindingId; // for instances grouped
    private Instant slaDueAt;
    private String slaStatus; // WITHIN_SLA, APPROACHING, BREACHED
}
