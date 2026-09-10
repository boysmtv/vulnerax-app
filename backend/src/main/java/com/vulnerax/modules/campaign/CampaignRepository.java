package com.vulnerax.modules.campaign;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface CampaignRepository extends JpaRepository<SecurityCampaign, UUID> { List<SecurityCampaign> findByOrganizationId(UUID orgId); }
