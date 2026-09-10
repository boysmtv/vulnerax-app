package com.vulnerax.modules.identity;

import com.vulnerax.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

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

    private String mfaSecret; // TOTP secret

    private String ssoProvider; // SAML, OIDC, LDAP

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Builder.Default
    private Set<String> authorities = new HashSet<>();

    public enum Role {
        ORG_OWNER, SECURITY_ADMIN, SECURITY_ENGINEER, PENTESTER, DEVELOPER, TECH_LEAD, AUDITOR, VIEWER, CLIENT
    }
}
