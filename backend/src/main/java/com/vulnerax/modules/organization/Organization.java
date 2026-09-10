package com.vulnerax.modules.organization;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

@Entity @Table(name = "organizations")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Organization extends BaseEntity {
    @Column(nullable = false, unique = true) private String name;
    @Column(nullable = false, unique = true) private String slug;
    private String description;
    @Builder.Default private String tier = "ENTERPRISE";
    @Builder.Default private Boolean active = true;
}
