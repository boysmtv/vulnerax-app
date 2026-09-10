package com.vulnerax.modules.notification;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name="notifications")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Notification extends BaseEntity {
    private UUID organizationId;
    private UUID projectId;
    @Column(nullable=false) private String type;
    @Column(nullable=false) private String channel;
    @Column(nullable=false) private String recipient;
    @Column(nullable=false) private String subject;
    @Column(columnDefinition="TEXT") private String body;
    @Builder.Default private String status = "PENDING";
}
