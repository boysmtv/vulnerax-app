package com.vulnerax.modules.campaign;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="security_campaigns")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SecurityCampaign extends BaseEntity {
    @Column(nullable=false) private UUID organizationId;
    @Column(nullable=false) private String name;
    @Column(columnDefinition="TEXT") private String description;
    @Column(columnDefinition="TEXT") private String queryJson;
    @Builder.Default private String status = "ACTIVE";
    @Builder.Default private Integer affectedCount = 0;
    @Builder.Default private Integer resolvedCount = 0;
}
