package com.vulnerax.modules.firmware;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="firmware_assets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class FirmwareAsset extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String name;
    private String version;
    @Column(nullable=false) private String fileName;
    private Long fileSize;
    private String sha256;
    @Column(columnDefinition="TEXT") private String filesystemJson;
    @Column(columnDefinition="TEXT") @Builder.Default private String binariesJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String cveJson = "[]";
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
