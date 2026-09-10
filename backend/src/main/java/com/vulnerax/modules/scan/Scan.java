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
    @Column(nullable = false) private String profile; // PASSIVE, QUICK, STANDARD, DEEP, RELEASE_GATE, CONTINUOUS, COMPLIANCE, PENTEST
    @Column(nullable = false) private String scannerType; // SAST, SCA, SECRET, DAST, API, MOBILE, CONTAINER, K8S, IAC, CLOUD, NETWORK
    @Builder.Default private String status = "QUEUED"; // QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    private String target; // repo url, image, domain, apk name
    private Instant startedAt;
    private Instant finishedAt;
    private String initiatedBy;
    @Column(columnDefinition = "TEXT") private String configJson;
    @Column(columnDefinition = "TEXT") private String scopeJson; // allowed targets, excluded paths
    private Integer findingsCount;
    private Long durationMs;
}
