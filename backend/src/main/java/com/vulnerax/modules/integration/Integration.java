package com.vulnerax.modules.integration;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="integrations")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Integration extends BaseEntity {
    @Column(nullable=false) private UUID organizationId;
    @Column(nullable=false) private String type;
    @Column(nullable=false) private String provider;
    @Column(nullable=false) private String name;
    @Column(columnDefinition="TEXT") @Builder.Default private String configurationJson = "{}";
    @Column(columnDefinition="TEXT") private String credentialsEncrypted;
    @Builder.Default private String status = "ACTIVE";
}
