package com.vulnerax.modules.oneclick;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

@Entity @Table(name = "oneclick_runs")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class OneClickRun extends BaseEntity {
    private java.util.UUID projectId;
    @Column(nullable = false, length = 1000) private String target;
    private String detectedType;
    @Builder.Default private String status = "QUEUED"; // QUEUED, RUNNING, COMPLETED, FAILED
    @Builder.Default private Integer progress = 0; // 0-100
    private Integer totalScans;
    @Builder.Default private Integer completedScans = 0;
    private Integer findingsCount;
    private java.util.UUID reportId;
    @Column(columnDefinition = "TEXT") private String scanIdsJson; // JSON array of scan IDs
    @Column(columnDefinition = "TEXT") private String message;
}
