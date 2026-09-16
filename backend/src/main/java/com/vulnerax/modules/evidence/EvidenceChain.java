package com.vulnerax.modules.evidence;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity @Table(name = "evidence_chain", indexes = {
    @Index(columnList = "findingId"), @Index(columnList = "scanId"),
    @Index(columnList = "evidenceType"), @Index(columnList = "createdAt")
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class EvidenceChain extends BaseEntity {

    @Column(nullable = false) private UUID findingId;
    private UUID scanId;
    private UUID assetId;

    @Column(nullable = false) private String evidenceType;
    // DNS_RESOLUTION, TCP_CONNECTIVITY, HTTP_RESPONSE, HEADER_ANALYSIS,
    // PAYLOAD_INJECTION, RESPONSE_COMPARISON, REPRODUCTION_ATTEMPT,
    // SCAN_CONNECTIVITY, AUTHENTICATION_RESULT

    @Column(nullable = false) private String status;
    // CONFIRMED, REFUTED, INCONCLUSIVE, BLOCKED, TIMEOUT

    @Column(columnDefinition = "TEXT") private String description;

    // Structured evidence fields
    @Column(columnDefinition = "TEXT") private String dnsEvidence;
    @Column(columnDefinition = "TEXT") private String tcpEvidence;
    @Column(columnDefinition = "TEXT") private String httpEvidence;
    @Column(columnDefinition = "TEXT") private String payloadEvidence;
    @Column(columnDefinition = "TEXT") private String responseEvidence;
    @Column(columnDefinition = "TEXT") private String comparisonEvidence;

    // Metadata
    private String scannerNode;
    private String scannerVersion;
    private Integer attempts;
    private Long durationMs;
    private Instant timestamp;

    // Confidence
    private Double detectionConfidence;
    private Double classificationConfidence;
    private Double vulnerabilityConfidence;

    // Evidence Strength
    private String evidenceStrength;
    // NONE, WEAK, MODERATE, STRONG, CONFIRMED

    @Column(columnDefinition = "TEXT") private String rawObservation;
    @Column(columnDefinition = "TEXT") private String normalizedObservation;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) timestamp = Instant.now();
    }
}
