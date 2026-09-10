package com.vulnerax.modules.coverage;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="security_coverages", uniqueConstraints=@UniqueConstraint(columnNames={"projectId","domain"}))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SecurityCoverage extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String domain;
    @Builder.Default private String status = "NOT_TESTED";
    @Builder.Default private Integer coveragePercent = 0;
    @Column(columnDefinition="TEXT") @Builder.Default private String detailsJson = "{}";
}
