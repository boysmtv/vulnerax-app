package com.vulnerax.modules.policy;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name="policy_exceptions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PolicyException extends BaseEntity {
    @Column(nullable=false) private UUID policyId;
    private UUID findingId;
    @Column(nullable=false, columnDefinition="TEXT") private String reason;
    @Column(nullable=false) private String owner;
    @Column(nullable=false) private String approver;
    @Column(nullable=false) private Instant expiration;
    @Column(columnDefinition="TEXT") private String compensatingControl;
    @Builder.Default private String status = "PENDING";
}
