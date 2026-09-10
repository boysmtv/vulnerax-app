package com.vulnerax.modules.sbom;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "sboms")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Sbom extends BaseEntity {
    @Column(nullable = false) private UUID projectId;
    private UUID assetId;
    @Column(nullable = false) private String format; // CYCLONEDX, SPDX
    @Column(nullable = false) private String version;
    @Column(columnDefinition = "TEXT") private String contentJson;
    @Builder.Default private Integer componentCount = 0;
    @Builder.Default private Integer vulnerableCount = 0;
}
