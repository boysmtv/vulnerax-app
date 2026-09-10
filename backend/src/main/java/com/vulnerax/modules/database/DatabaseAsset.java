package com.vulnerax.modules.database;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="database_assets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DatabaseAsset extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String name;
    @Column(nullable=false) private String engine;
    private String version;
    @Column(nullable=false) private String host;
    @Column(nullable=false) private Integer port;
    @Column(columnDefinition="TEXT") private String exposureJson;
    @Column(columnDefinition="TEXT") private String encryptionJson;
    @Column(columnDefinition="TEXT") private String authJson;
    @Column(columnDefinition="TEXT") private String auditJson;
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
