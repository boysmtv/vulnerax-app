package com.vulnerax.modules.organization;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "workspaces")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Workspace extends BaseEntity {
    @Column(nullable = false) private String name;
    @Column(nullable = false) private UUID organizationId;
    private String description;
    @Builder.Default private String environment = "PRODUCTION"; // DEV, QA, STAGING, PRODUCTION, DR
}
