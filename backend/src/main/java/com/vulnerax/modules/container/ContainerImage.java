package com.vulnerax.modules.container;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="container_images")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ContainerImage extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String imageName;
    @Builder.Default private String tag = "latest";
    private String digest;
    private String baseImage;
    @Column(columnDefinition="TEXT") private String dockerfile;
    @Column(columnDefinition="TEXT") @Builder.Default private String packagesJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String cveJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String misconfigJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String secretJson = "[]";
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
