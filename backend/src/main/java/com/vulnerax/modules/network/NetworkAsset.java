package com.vulnerax.modules.network;
import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
@Entity @Table(name="network_assets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class NetworkAsset extends BaseEntity {
    @Column(nullable=false) private UUID projectId;
    @Column(nullable=false) private String host;
    private String ip;
    @Column(nullable=false) private Integer port;
    private String service;
    private String version;
    @Builder.Default private String protocol = "TCP";
    @Column(columnDefinition="TEXT") private String tlsJson;
    @Column(columnDefinition="TEXT") private String certJson;
    @Column(columnDefinition="TEXT") private String vulnJson;
    @Builder.Default private String status = "OPEN";
}
