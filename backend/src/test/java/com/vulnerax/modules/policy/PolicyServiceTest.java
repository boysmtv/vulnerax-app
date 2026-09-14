package com.vulnerax.modules.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyServiceTest {

    @Mock PolicyRepository policyRepo;
    @Mock PolicyExceptionRepository exRepo;
    @InjectMocks PolicyService service;

    // create
    @Test
    void create_savesPolicy() {
        SecurityPolicy p = SecurityPolicy.builder().name("Block Critical").organizationId(UUID.randomUUID()).build();
        SecurityPolicy saved = SecurityPolicy.builder().name("Block Critical").organizationId(p.getOrganizationId()).build();
        saved.setId(UUID.randomUUID());
        when(policyRepo.save(any())).thenReturn(saved);
        var result = service.create(p);
        assertThat(result.getId()).isNotNull();
    }

    @Test
    void create_nullRuleJson_setsDefault() {
        SecurityPolicy p = SecurityPolicy.builder().name("Test").organizationId(UUID.randomUUID()).ruleJson(null).build();
        when(policyRepo.save(any())).thenAnswer(i -> {
            SecurityPolicy arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(p);
        assertThat(p.getRuleJson()).contains("No Critical in production");
    }

    @Test
    void create_existingRuleJson_kept() {
        SecurityPolicy p = SecurityPolicy.builder().name("Test").organizationId(UUID.randomUUID())
                .ruleJson("{\"custom\":\"rule\"}").build();
        when(policyRepo.save(any())).thenAnswer(i -> {
            SecurityPolicy arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        service.create(p);
        assertThat(p.getRuleJson()).contains("custom");
    }

    // list
    @Test
    void list_withOrgId_filtersByOrg() {
        UUID orgId = UUID.randomUUID();
        when(policyRepo.findByOrganizationId(orgId)).thenReturn(List.of(
                SecurityPolicy.builder().name("P1").organizationId(orgId).build()
        ));
        var list = service.list(orgId);
        assertThat(list).hasSize(1);
        verify(policyRepo).findByOrganizationId(orgId);
        verify(policyRepo, never()).findAll();
    }

    @Test
    void list_nullOrgId_returnsAll() {
        when(policyRepo.findAll()).thenReturn(List.of());
        var list = service.list(null);
        assertThat(list).isEmpty();
        verify(policyRepo).findAll();
    }

    // get
    @Test
    void get_found() {
        UUID id = UUID.randomUUID();
        SecurityPolicy p = SecurityPolicy.builder().name("Policy").organizationId(UUID.randomUUID()).build();
        p.setId(id);
        when(policyRepo.findById(id)).thenReturn(Optional.of(p));
        assertThat(service.get(id).getName()).isEqualTo("Policy");
    }

    @Test
    void get_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(policyRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id))
                .isInstanceOf(NoSuchElementException.class);
    }

    // createException
    @Test
    void createException_saves() {
        PolicyException e = PolicyException.builder()
                .policyId(UUID.randomUUID()).reason("Accepted risk")
                .owner("admin").approver("ciso")
                .expiration(Instant.now().plusSeconds(86400)).build();
        PolicyException saved = PolicyException.builder()
                .policyId(e.getPolicyId()).reason("Accepted risk")
                .owner("admin").approver("ciso").expiration(e.getExpiration()).build();
        saved.setId(UUID.randomUUID());
        when(exRepo.save(any())).thenReturn(saved);
        var result = service.createException(e);
        assertThat(result.getId()).isNotNull();
    }

    // listExceptions
    @Test
    void listExceptions_returnsList() {
        UUID policyId = UUID.randomUUID();
        when(exRepo.findByPolicyId(policyId)).thenReturn(List.of(
                PolicyException.builder().policyId(policyId).reason("Ex1").build()
        ));
        var list = service.listExceptions(policyId);
        assertThat(list).hasSize(1);
    }

    // evaluate
    @Test
    void evaluate_returnsPolicyResult() {
        UUID policyId = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        SecurityPolicy p = SecurityPolicy.builder().name("Gate1").organizationId(UUID.randomUUID())
                .ruleJson("{\"gate\":\"test\"}").build();
        p.setId(policyId);
        when(policyRepo.findById(policyId)).thenReturn(Optional.of(p));
        var result = service.evaluate(policyId, projectId);
        assertThat(result).containsKey("policy");
        assertThat(result).containsKey("result");
        assertThat(result).containsKey("details");
        assertThat(result).containsKey("projectId");
        assertThat(result.get("policy")).isEqualTo("Gate1");
        assertThat(result.get("result")).isIn("PASS", "BLOCKED");
    }

    @Test
    void evaluate_nullProjectId_usesPlaceholder() {
        UUID policyId = UUID.randomUUID();
        SecurityPolicy p = SecurityPolicy.builder().name("Gate2").organizationId(UUID.randomUUID())
                .ruleJson("{}").build();
        p.setId(policyId);
        when(policyRepo.findById(policyId)).thenReturn(Optional.of(p));
        var result = service.evaluate(policyId, null);
        assertThat(result.get("projectId")).isEqualTo("-");
    }

    // defaults
    @Test
    void defaults_returnsFourPolicies() {
        var list = service.defaults(UUID.randomUUID());
        assertThat(list).hasSize(4);
    }

    @Test
    void defaults_eachEntryHasNameRuleSeverity() {
        var list = service.defaults(null);
        for (Map<String, Object> entry : list) {
            assertThat(entry).containsKeys("name", "rule", "severity");
        }
    }

    @Test
    void defaults_includesCriticalPolicies() {
        var list = service.defaults(null);
        var names = list.stream().map(e -> (String) e.get("name")).toList();
        assertThat(names).anyMatch(n -> n.contains("Critical"));
        assertThat(names).anyMatch(n -> n.contains("KEV"));
        assertThat(names).anyMatch(n -> n.contains("secrets"));
        assertThat(names).anyMatch(n -> n.contains("SBOM"));
    }
}
