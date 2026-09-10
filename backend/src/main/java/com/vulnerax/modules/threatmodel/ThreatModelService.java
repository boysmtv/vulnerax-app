package com.vulnerax.modules.threatmodel;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;

@Service @RequiredArgsConstructor
public class ThreatModelService {
    private final ThreatModelRepository repo;

    public ThreatModel create(ThreatModel m) {
        if (m.getComponentsJson()==null) m.setComponentsJson("[{\"id\":\"web\",\"name\":\"Web Frontend\",\"type\":\"Browser\"},{\"id\":\"api\",\"name\":\"API Gateway\",\"type\":\"Service\"},{\"id\":\"db\",\"name\":\"PostgreSQL\",\"type\":\"Database\"}]");
        if (m.getDataflowsJson()==null) m.setDataflowsJson("[{\"from\":\"web\",\"to\":\"api\",\"data\":\"HTTPS JSON\"},{\"from\":\"api\",\"to\":\"db\",\"data\":\"SQL\"}]");
        if (m.getTrustBoundariesJson()==null) m.setTrustBoundariesJson("[{\"id\":\"tb1\",\"name\":\"Internet → DMZ\",\"components\":[\"web\",\"api\"]}]");
        if (m.getThreatsJson()==null) m.setThreatsJson(generateSTRIDE());
        if (m.getControlsJson()==null) m.setControlsJson("[{\"id\":\"C1\",\"name\":\"OAuth2 OIDC\",\"covers\":\"STRIDE-S\"},{\"id\":\"C2\",\"name\":\"WAF + Input Validation\",\"covers\":\"T/I\"}]");
        return repo.save(m);
    }

    private String generateSTRIDE() {
        return "[{\"id\":\"T1\",\"category\":\"STRIDE-S\",\"title\":\"Spoofing API client\",\"mitigation\":\"mTLS + JWT\"}," +
               "{\"id\":\"T2\",\"category\":\"STRIDE-T\",\"title\":\"Tampering DB query\",\"mitigation\":\"Parameterized queries\"}," +
               "{\"id\":\"T3\",\"category\":\"STRIDE-R\",\"title\":\"Repudiation of payment\",\"mitigation\":\"Audit log immutable\"}," +
               "{\"id\":\"T4\",\"category\":\"STRIDE-I\",\"title\":\"Information Disclosure via API\",\"mitigation\":\"BOLA check\"}," +
               "{\"id\":\"T5\",\"category\":\"STRIDE-D\",\"title\":\"DoS on search endpoint\",\"mitigation\":\"Rate limit + Redis\"}," +
               "{\"id\":\"T6\",\"category\":\"STRIDE-E\",\"title\":\"Elevation via IAM wildcard\",\"mitigation\":\"Least privilege RBAC\"}]";
    }

    public List<ThreatModel> list(UUID projectId) { return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public ThreatModel get(UUID id) { return repo.findById(id).orElseThrow(); }
}
