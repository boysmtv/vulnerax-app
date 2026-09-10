package com.vulnerax.modules.retest;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="retests")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Retest extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    private UUID findingId;
    private UUID assetId;
    private UUID scanId;
    @Builder.Default private String type = "FINDING";
    @Builder.Default private String status = "PENDING";
    private String requestedBy;
    private String result; // PASS/FAIL/PARTIAL
    @Column(columnDefinition="TEXT") private String evidenceJson;
    @Column(columnDefinition="TEXT") private String beforeJson;
    @Column(columnDefinition="TEXT") private String afterJson;
}
