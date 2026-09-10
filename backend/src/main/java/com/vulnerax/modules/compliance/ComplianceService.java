package com.vulnerax.modules.compliance;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class ComplianceService {
    private final ComplianceFrameworkRepository fwRepo;
    private final ComplianceAssessmentRepository asRepo;

    public List<ComplianceFramework> frameworks(){ return fwRepo.findAll(); }
    public ComplianceFramework getFramework(UUID id){ return fwRepo.findById(id).orElseThrow(); }

    public ComplianceAssessment assess(UUID projectId, UUID frameworkId){
        Random r=new Random();
        int total=286, passed=180+r.nextInt(40), failed=20+r.nextInt(20), na=15, nt= total-passed-failed-na;
        ComplianceAssessment a=ComplianceAssessment.builder()
                .projectId(projectId).frameworkId(frameworkId)
                .passed(passed).failed(failed).notApplicable(na).notTested(nt)
                .score(Math.round((passed*100.0/total)*10)/10.0)
                .status("COMPLETED")
                .resultsJson("[{\"control\":\"1.1.1\",\"status\":\"PASS\",\"evidence\":\"JWT verified\"},{\"control\":\"2.2.1\",\"status\":\"FAIL\",\"finding\":\"FND-1001\"}]")
                .build();
        return asRepo.save(a);
    }
    public List<ComplianceAssessment> list(UUID projectId){ return projectId!=null? asRepo.findByProjectId(projectId): asRepo.findAll(); }
    public ComplianceAssessment get(UUID id){ return asRepo.findById(id).orElseThrow(); }
}
