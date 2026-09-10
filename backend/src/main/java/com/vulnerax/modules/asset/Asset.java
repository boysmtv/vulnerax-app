package com.vulnerax.modules.asset;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity @Table(name = "assets", indexes = {@Index(columnList = "projectId"), @Index(columnList = "type")})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Asset extends BaseEntity {

    @Column(nullable = false) private UUID projectId;
    @Column(nullable = false) private UUID organizationId;
    private UUID workspaceId;

    @Column(nullable = false) private String name;
    @Column(nullable = false) private String type; // DOMAIN, SUBDOMAIN, IP, URL, WEBAPP, API, REPO, PACKAGE, MOBILE_APP, CONTAINER_IMAGE, K8S_CLUSTER, CLOUD_ACCOUNT, DB, BUCKET, QUEUE, etc

    private String identifier; // e.g. domain, image digest, repo url
    private String version;
    private String environment; // DEV, QA, STAGING, PRODUCTION
    @Builder.Default private String criticality = "MEDIUM"; // LOW,MEDIUM,HIGH,CRITICAL
    @Builder.Default private String dataClassification = "INTERNAL"; // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    @Builder.Default private Boolean internetExposed = false;
    @Builder.Default private Boolean managed = true;
    @Builder.Default private String status = "ACTIVE"; // ACTIVE, DEPRECATED, UNKNOWN, SHADOW
    @Builder.Default private String technology = "UNKNOWN";
    private String owner;
    private String team;
    private String location; // region
    private String tags; // comma sep for simple
    @Column(columnDefinition = "TEXT") private String metadataJson;
    @Column(columnDefinition = "TEXT") private String discoverySource; // GITHUB, AWS, MANUAL, etc
}
