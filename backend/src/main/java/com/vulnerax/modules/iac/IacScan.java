package com.vulnerax.modules.iac;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="iac_scans")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class IacScan extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    private String repository;
    @Column(nullable=false) private String filePath;
    @Builder.Default private String tool = "CHECKOV";
    @Column(columnDefinition="TEXT") @Builder.Default private String findingsJson = "[]";
    @Builder.Default private Integer passed = 0;
    @Builder.Default private Integer failed = 0;
    @Builder.Default private String status = "COMPLETED";
}
