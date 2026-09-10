package com.vulnerax.modules.retest;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class RetestService {
    private final RetestRepository repo;
    public Retest request(Retest r){
        r.setStatus("IN_PROGRESS");
        // mock compare before/after
        r.setBeforeJson("{\"severity\":\"HIGH\",\"evidence\":\"SQL injection payload works\"}");
        new Thread(() -> {
            try { Thread.sleep(1200); } catch(Exception e){}
            r.setAfterJson("{\"severity\":\"NONE\",\"evidence\":\"Parameterized query verified\"}");
            r.setResult(Math.random()>0.2? "PASS":"FAIL");
            r.setStatus("COMPLETED");
            r.setEvidenceJson("{\"request\":\"GET /accounts/123\",\"response\":\"403 Forbidden\"}");
            repo.save(r);
        }).start();
        return repo.save(r);
    }
    public List<Retest> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public Retest get(UUID id){ return repo.findById(id).orElseThrow(); }
}
