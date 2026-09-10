package com.vulnerax.modules.reporting;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "reports")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Report extends BaseEntity {
    @Column(nullable = false) private UUID projectId;
    @Column(nullable = false) private String type; // EXECUTIVE, TECHNICAL, DEVELOPER, PENTEST, RETEST, COMPLIANCE, SUPPLY_CHAIN, POSTURE, ATTACK_SURFACE
    @Column(nullable = false) private String title;
    private String format; // PDF, HTML, JSON, CSV, SARIF
    @Builder.Default private String status = "DRAFT"; // DRAFT, GENERATING, READY, FAILED
    @Column(columnDefinition = "TEXT") private String contentJson; // sections json
    private String generatedBy;
    private String filePath; // S3 path
    private String classification; // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
}
