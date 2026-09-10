package com.vulnerax.modules.aillm;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="ai_assets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AiAsset extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String name;
    @Column(nullable=false) private String type;
    private String model;
    private String provider;
    @Column(columnDefinition="TEXT") @Builder.Default private String endpointsJson = "[]";
    @Column(columnDefinition="TEXT") private String ragnJson;
    @Column(columnDefinition="TEXT") @Builder.Default private String findingsJson = "[]";
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
