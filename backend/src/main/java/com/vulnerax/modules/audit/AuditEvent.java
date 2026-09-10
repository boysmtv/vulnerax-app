package com.vulnerax.modules.audit;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

@Entity @Table(name = "audit_events")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AuditEvent extends BaseEntity {
    @Column(nullable = false) private String action; // e.g. FINDING_CREATED, LOGIN, SCAN_CREATED
    private String entityType;
    private String entityId;
    private String actor;
    @Column(columnDefinition = "TEXT") private String details;
    private String ipAddress;
}
