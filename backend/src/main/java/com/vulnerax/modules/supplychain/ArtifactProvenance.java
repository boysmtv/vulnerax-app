package com.vulnerax.modules.supplychain;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="artifact_provenances")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ArtifactProvenance extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String artifactName;
    @Column(nullable=false) private String version;
    private UUID sbomId;
    @Column(columnDefinition="TEXT") private String signatureJson;
    @Column(columnDefinition="TEXT") private String buildJson;
    @Column(columnDefinition="TEXT") private String provenanceJson;
    @Builder.Default private Boolean verified = false;
    @Builder.Default private String status = "ACTIVE";
}
