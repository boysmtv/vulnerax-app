package com.vulnerax.modules.finding;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "evidences")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Evidence extends BaseEntity {
    @Column(nullable = false) private UUID findingId;
    private UUID assetId;
    private UUID scanId;
    @Column(nullable = false) private String type; // SCREENSHOT, HTTP_REQUEST, HTTP_RESPONSE, LOG, FILE, CODE_SNIPPET, STACK_TRACE, SCANNER_RESULT, VIDEO, CONFIG
    @Column(columnDefinition = "TEXT") private String content; // masked if secret
    private String fileName;
    private String mimeType;
    private String sha256;
    private String author;
    @Builder.Default private Boolean sensitive = false;
}
