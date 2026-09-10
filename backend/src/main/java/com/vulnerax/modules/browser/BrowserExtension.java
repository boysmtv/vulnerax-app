package com.vulnerax.modules.browser;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="browser_extensions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class BrowserExtension extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String name;
    @Column(nullable=false, columnDefinition="TEXT") private String manifestJson;
    @Column(columnDefinition="TEXT") @Builder.Default private String permissionsJson = "[]";
    @Column(columnDefinition="TEXT") @Builder.Default private String findingsJson = "[]";
    @Builder.Default private String riskLevel = "MEDIUM";
    @Builder.Default private String status = "ACTIVE";
}
