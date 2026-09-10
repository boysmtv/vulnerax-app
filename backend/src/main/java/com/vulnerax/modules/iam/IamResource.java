package com.vulnerax.modules.iam;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="iam_resources")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IamResource extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Builder.Default private String provider = "AWS";
    @Column(nullable=false) private String principalType;
    @Column(nullable=false) private String principalName;
    @Column(columnDefinition="TEXT") @Builder.Default private String policiesJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String permissionsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String riskJson = "{}";
    @Builder.Default private Boolean isExcessive = false;
    @Builder.Default private Boolean isDormant = false;
    @Builder.Default private String status = "ACTIVE";
}
