package com.vulnerax.modules.finding;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "evidence")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Evidence extends BaseEntity {
    @Column(nullable = false) private UUID findingId;
    @Column(nullable = false) private String type;
    @Column(columnDefinition = "TEXT") private String content;
    private String author;
    private String sha256;
    private String requestMethod;
    private String requestUrl;
    @Column(columnDefinition = "TEXT") private String requestBody;
    private int responseStatusCode;
    @Column(columnDefinition = "TEXT") private String responseBody;
    @Column(columnDefinition = "TEXT") private String payload;
    private String command;
    @Column(columnDefinition = "TEXT") private String commandOutput;
    private String screenshot;
    private String validationHash;
    private boolean validated;
}
