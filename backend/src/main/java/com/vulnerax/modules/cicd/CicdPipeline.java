package com.vulnerax.modules.cicd;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="cicd_pipelines")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CicdPipeline extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String platform;
    @Column(nullable=false) private String repository;
    @Column(nullable=false) private String pipelineName;
    @Column(columnDefinition="TEXT") private String configurationJson;
    @Column(columnDefinition="TEXT") @Builder.Default private String findingsJson = "[]";
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
