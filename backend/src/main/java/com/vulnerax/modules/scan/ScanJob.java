package com.vulnerax.modules.scan;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "scan_jobs")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ScanJob extends BaseEntity {
    @Column(nullable = false) private UUID scanId;
    @Column(nullable = false) private String scannerPlugin; // semgrep, trivy, zap, mobsf, gitleaks, etc
    @Builder.Default private String status = "QUEUED";
    private String workerId;
    private String logs;
    private Integer progress; // 0-100
    @Column(columnDefinition = "TEXT") private String resultJson;
    @Column(columnDefinition = "TEXT") private String error;
}
