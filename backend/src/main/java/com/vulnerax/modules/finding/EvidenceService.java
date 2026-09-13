package com.vulnerax.modules.finding;

import com.vulnerax.modules.audit.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EvidenceService {

    private final EvidenceRepository evidenceRepo;
    private final AuditService auditService;

    public List<Evidence> getByFinding(UUID findingId) {
        return evidenceRepo.findByFindingId(findingId);
    }

    public long getValidatedCount() {
        return evidenceRepo.countValidated();
    }

    @Transactional
    public Evidence create(Evidence evidence) {
        if (evidence.getSha256() == null && evidence.getContent() != null) {
            evidence.setSha256(computeSha256(evidence.getContent()));
        }
        Evidence saved = evidenceRepo.save(evidence);
        auditService.log("EVIDENCE_CREATED", "Evidence", saved.getId().toString(),
                "type=" + evidence.getType() + " findingId=" + evidence.getFindingId());
        return saved;
    }

    @Transactional
    public Evidence validate(UUID evidenceId, String validationHash) {
        Evidence ev = evidenceRepo.findById(evidenceId)
                .orElseThrow(() -> new com.vulnerax.common.exception.ResourceNotFoundException("Evidence not found"));
        ev.setValidated(true);
        ev.setValidationHash(validationHash);
        Evidence saved = evidenceRepo.save(ev);
        auditService.log("EVIDENCE_VALIDATED", "Evidence", saved.getId().toString(),
                "findingId=" + ev.getFindingId());
        return saved;
    }

    @Transactional
    public Evidence createHttpEvidence(UUID findingId, String method, String url, int statusCode,
                                        String headers, String body, String payload, long responseTimeMs) {
        Evidence ev = Evidence.builder()
                .findingId(findingId)
                .type("HTTP_REQUEST")
                .requestMethod(method)
                .requestUrl(url)
                .responseStatusCode(statusCode)
                .responseHeaders(headers)
                .responseBody(body != null ? body.substring(0, Math.min(body.length(), 5000)) : "")
                .payload(payload)
                .responseTimeMs(responseTimeMs)
                .author("dast-analyzer")
                .sha256(computeSha256(url + statusCode + (body != null ? body.substring(0, Math.min(body.length(), 1000)) : "")))
                .build();
        return evidenceRepo.save(ev);
    }

    @Transactional
    public Evidence createCodeEvidence(UUID findingId, String file, int line, String snippet, String source) {
        String content = file + ":" + line + "\n" + snippet;
        Evidence ev = Evidence.builder()
                .findingId(findingId)
                .type("CODE_SNIPPET")
                .content(content)
                .requestUrl(file)
                .author(source)
                .sha256(computeSha256(content))
                .build();
        return evidenceRepo.save(ev);
    }

    private String computeSha256(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return java.util.UUID.randomUUID().toString().replace("-", "");
        }
    }
}
