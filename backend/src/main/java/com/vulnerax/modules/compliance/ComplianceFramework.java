package com.vulnerax.modules.compliance;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
@Entity @Table(name="compliance_frameworks")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ComplianceFramework extends BaseEntity {
    @Column(nullable=false, unique=true) private String name;
    @Column(nullable=false) private String version;
    @Column(columnDefinition="TEXT") private String description;
    @Builder.Default private String type = "STANDARD";
    @Column(columnDefinition="TEXT") @Builder.Default private String controlsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String mappingJson = "{}";
}
