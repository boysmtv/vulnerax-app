package com.vulnerax.modules.identity;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User extends BaseEntity {

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Role role = Role.DEVELOPER;

    @Column(nullable = false)
    @Builder.Default
    private Boolean mfaEnabled = false;

    private String mfaSecret;

    private String ssoProvider;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Builder.Default
    private Set<String> authorities = new HashSet<>();

    private UUID organizationId;

    @Column(columnDefinition = "TEXT")
    @Convert(converter = StringListConverter.class)
    private List<String> recoveryCodes;

    public enum Role {
        ORG_OWNER, SECURITY_ADMIN, SECURITY_ENGINEER, PENTESTER, DEVELOPER, TECH_LEAD, AUDITOR, VIEWER, CLIENT
    }

    @Converter
    public static class StringListConverter implements AttributeConverter<List<String>, String> {
        @Override
        public String convertToDatabaseColumn(List<String> list) {
            if (list == null) return null;
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(list);
            } catch (Exception e) { return "[]"; }
        }

        @Override
        public List<String> convertToEntityAttribute(String data) {
            if (data == null || data.isEmpty()) return List.of();
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().readValue(data,
                        new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {});
            } catch (Exception e) { return List.of(); }
        }
    }
}
