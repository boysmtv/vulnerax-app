package com.vulnerax.modules.organization;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "projects")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Project extends BaseEntity {
    @Column(nullable = false) private String name;
    @Column(nullable = false) private UUID workspaceId;
    @Column(nullable = false) private UUID organizationId;
    private String description;
    @Builder.Default private String criticality = "HIGH"; // LOW, MEDIUM, HIGH, CRITICAL
    @Builder.Default private String status = "ACTIVE";
    private String businessUnit;
    private String techLead;
    private String securityChampion;
}
