package com.vulnerax.modules.k8s;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="k8s_resources")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class K8sResource extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String clusterName;
    @Builder.Default private String namespace = "default";
    @Column(nullable=false) private String kind;
    @Column(nullable=false) private String name;
    @Column(columnDefinition="TEXT") private String configurationJson;
    @Column(columnDefinition="TEXT") private String riskJson;
    @Builder.Default private String status = "ACTIVE";
}
