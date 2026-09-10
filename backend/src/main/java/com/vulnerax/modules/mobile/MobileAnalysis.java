package com.vulnerax.modules.mobile;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "mobile_analyses")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MobileAnalysis extends BaseEntity {
    @Column(nullable = false) private UUID projectId;
    private UUID assetId;
    @Column(nullable = false) private String platform; // ANDROID, IOS
    @Column(nullable = false) private String fileName; // app.apk
    private String fileSha256;
    private Long fileSize;
    @Column(columnDefinition = "TEXT") private String manifestJson;
    @Column(columnDefinition = "TEXT") private String stringsJson;
    @Column(columnDefinition = "TEXT") private String findingsJson;
    @Column(columnDefinition = "TEXT") private String certInfo;
    @Builder.Default private Integer masvsScore = 0;
    private String status; // QUEUED, ANALYZING, DONE, FAILED
}
