package com.vulnerax.modules.scan;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity @Table(name = "scans")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Scan extends BaseEntity {
    @Column(nullable = false) private UUID projectId;
    private UUID assetId;
    private UUID organizationId;
    @Column(nullable = false) private String profile;
    @Column(nullable = false) private String scannerType;
    @Column(nullable = false) private String scanType;
    @Builder.Default private String status = "QUEUED";
    private String target;
    private String targetUrl;
    private Instant startedAt;
    private Instant finishedAt;
    private String initiatedBy;
    @Column(columnDefinition = "TEXT") private String configJson;
    @Column(columnDefinition = "TEXT") private String scopeJson;
    private Integer findingsCount;
    private Long durationMs;
}
