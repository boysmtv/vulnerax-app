package com.vulnerax.modules.cloud;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="cloud_resources")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CloudResource extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String provider;
    @Column(nullable=false) private String accountId;
    @Column(nullable=false) private String region;
    @Column(nullable=false) private String service;
    @Column(nullable=false) private String resourceType;
    @Column(nullable=false) private String resourceId;
    private String name;
    @Column(columnDefinition="TEXT") private String configurationJson;
    @Column(columnDefinition="TEXT") private String riskJson;
    @Column(columnDefinition="TEXT") private String complianceJson;
    @Builder.Default private Boolean publicExposed = false;
    @Builder.Default private String status = "ACTIVE";
}
