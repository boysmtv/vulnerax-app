package com.vulnerax.modules.policy;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface PolicyExceptionRepository extends JpaRepository<PolicyException, UUID> { List<PolicyException> findByPolicyId(UUID policyId); }
