package com.vulnerax.modules.policy;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="security_policies")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SecurityPolicy extends BaseEntity {
    @Column(nullable=false) private UUID organizationId;
    @Column(nullable=false) private String name;
    @Column(columnDefinition="TEXT") private String description;
    @Column(columnDefinition="TEXT") private String ruleJson;
    @Builder.Default private String severity = "HIGH";
    @Builder.Default private Boolean enabled = true;
    @Builder.Default private String type = "GATE";
}
