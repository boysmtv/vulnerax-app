package com.vulnerax.modules.compliance;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="compliance_assessments")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ComplianceAssessment extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private UUID frameworkId;
    @Builder.Default private String status = "IN_PROGRESS";
    @Column(columnDefinition="TEXT") @Builder.Default private String resultsJson = "[]";
    @Builder.Default private Double score = 0.0;
    @Builder.Default private Integer passed = 0;
    @Builder.Default private Integer failed = 0;
    @Builder.Default private Integer notApplicable = 0;
    @Builder.Default private Integer notTested = 0;
}
