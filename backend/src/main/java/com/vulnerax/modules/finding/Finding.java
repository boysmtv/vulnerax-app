package com.vulnerax.modules.finding;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity @Table(name = "findings", indexes = {
    @Index(columnList = "projectId"), @Index(columnList = "severity"),
    @Index(columnList = "status"), @Index(columnList = "organizationId"),
    @Index(columnList = "assetId"), @Index(columnList = "scanId")
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Finding extends BaseEntity {

    @Column(nullable = false, unique = true) private String findingId;

    @Column(nullable = false) private String title;
    @Column(columnDefinition = "TEXT") private String description;
    @Column(nullable = false) private String type;
    @Column(nullable = false) private String severity;
    @Column(nullable = false) private String confidence;
    @Builder.Default private String status = "OPEN";

    private UUID projectId;
    private UUID organizationId;
    private UUID assetId;
    private String assetName;
    private String environment;

    private String source;
    private UUID scanId;

    private String cwe;
    private String owasp;
    private String masvs;
    private String asvs;
    private String cweId;

    private Double cvss;
    private Double epss;
    @Builder.Default private Boolean kev = false;
    @Builder.Default private Boolean internetExposed = false;
    @Builder.Default private Boolean reachable = false;
    private String businessCriticality;
    private String owner;
    private String filePath;
    private Integer lineNumber;
    private String functionName;
    @Column(columnDefinition = "TEXT") private String codeSnippet;
    @Column(columnDefinition = "TEXT") private String dataFlow;
    @Column(columnDefinition = "TEXT") private String recommendation;
    @Column(columnDefinition = "TEXT") private String evidenceJson;

    private Double riskScore;
    private String riskLevel;

    private String fingerprint;
    @Builder.Default private Boolean falsePositive = false;
    @Builder.Default private Boolean duplicate = false;

    private UUID parentFindingId;
    private UUID correlationId;
    private Instant slaDueAt;
    private String slaStatus;
}
