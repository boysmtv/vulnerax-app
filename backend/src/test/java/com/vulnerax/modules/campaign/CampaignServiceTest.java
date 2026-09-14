package com.vulnerax.modules.campaign;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CampaignServiceTest {

    @Mock CampaignRepository repo;
    @InjectMocks CampaignService service;

    private SecurityCampaign sampleCampaign() {
        return SecurityCampaign.builder()
                .organizationId(UUID.randomUUID())
                .name("Q1 Security Review")
                .description("Comprehensive security audit for Q1")
                .queryJson("{\"severity\":[\"HIGH\",\"CRITICAL\"]}")
                .build();
    }

    @Test
    void create_saves_and_returns() {
        SecurityCampaign camp = sampleCampaign();
        SecurityCampaign saved = sampleCampaign();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(camp);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(camp);
    }

    @Test
    void list_byOrgId() {
        UUID orgId = UUID.randomUUID();
        when(repo.findByOrganizationId(orgId)).thenReturn(List.of(sampleCampaign()));

        var result = service.list(orgId);

        assertThat(result).hasSize(1);
        verify(repo).findByOrganizationId(orgId);
    }

    @Test
    void list_all_when_no_orgId() {
        when(repo.findAll()).thenReturn(List.of(sampleCampaign(), sampleCampaign()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        SecurityCampaign camp = sampleCampaign();
        camp.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(camp));

        var result = service.get(id);

        assertThat(result.getId()).isEqualTo(id);
    }

    @Test
    void get_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.get(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
