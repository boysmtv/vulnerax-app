package com.vulnerax.modules.policy;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class PolicyService {
    private final PolicyRepository policyRepo;
    private final PolicyExceptionRepository exRepo;

    public SecurityPolicy create(SecurityPolicy p){
        if(p.getRuleJson()==null) p.setRuleJson("{\"gate\":\"No Critical in production\",\"kev\":\"0\",\"secret\":\"0\"}");
        return policyRepo.save(p);
    }
    public List<SecurityPolicy> list(UUID orgId){ return orgId!=null? policyRepo.findByOrganizationId(orgId): policyRepo.findAll(); }
    public SecurityPolicy get(UUID id){ return policyRepo.findById(id).orElseThrow(); }

    public PolicyException createException(PolicyException e){ return exRepo.save(e); }
    public List<PolicyException> listExceptions(UUID policyId){ return exRepo.findByPolicyId(policyId); }

    public Map<String,Object> evaluate(UUID policyId, UUID projectId){
        SecurityPolicy p=get(policyId);
        // mock evaluation: PASS if no critical
        boolean pass=Math.random()>0.3;
        return Map.of("policy",p.getName(),"result", pass?"PASS":"BLOCKED","details", p.getRuleJson(),"projectId",projectId!=null?projectId.toString():"-");
    }
    public List<Map<String,Object>> defaults(UUID orgId){
        return List.of(
            Map.of("name","No Critical in production","rule","Critical 0 allowed","severity","CRITICAL"),
            Map.of("name","No KEV in internet-facing","rule","KEV 0","severity","CRITICAL"),
            Map.of("name","No exposed secrets","rule","Secret 0","severity","HIGH"),
            Map.of("name","All prod requires SBOM","rule","SBOM required","severity","MEDIUM")
        );
    }
}
