package com.vulnerax.modules.finding;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity @Table(name = "finding_instances")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class FindingInstance extends BaseEntity {
    @Column(nullable = false) private UUID findingId;
    @Column(nullable = false) private String assetName;
    private String location; // file:line or endpoint
    private String scanner;
    @Column(columnDefinition = "TEXT") private String evidence;
    private String fingerprint;
}
