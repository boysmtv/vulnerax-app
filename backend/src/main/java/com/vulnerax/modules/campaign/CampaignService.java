package com.vulnerax.modules.campaign;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class CampaignService {
    private final CampaignRepository repo;
    public SecurityCampaign create(SecurityCampaign c){ return repo.save(c); }
    public List<SecurityCampaign> list(UUID orgId){ return orgId!=null? repo.findByOrganizationId(orgId): repo.findAll(); }
    public SecurityCampaign get(UUID id){ return repo.findById(id).orElseThrow(); }
}
