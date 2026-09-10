package com.vulnerax.modules.threatmodel;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="threat_models")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ThreatModel extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String name;
    @Column(columnDefinition="TEXT") private String description;
    @Builder.Default private String status = "DRAFT";
    @Column(columnDefinition="TEXT") @Builder.Default private String componentsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String dataflowsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String trustBoundariesJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String threatsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String controlsJson = "[]";
    @Column(columnDefinition="TEXT") private String diagramJson;
}
