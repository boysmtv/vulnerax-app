package com.vulnerax.modules.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiAnalystService {
    private final FindingRepository findingRepo;

    @Value("${app.ai.deepseek-api-key:}")
    private String deepseekKey;

    @Value("${app.ai.deepseek-base-url:https://api.deepseek.com}")
    private String deepseekBase;

    @Value("${app.ai.deepseek-model:deepseek-chat}")
    private String deepseekModel;

    private final ObjectMapper om = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public Map<String,Object> explain(UUID findingId) {
        Finding f = findingRepo.findById(findingId).orElseThrow(() -> new RuntimeException("Finding not found"));
        // Try DeepSeek real if key configured
        Map<String,Object> deep = tryDeepSeekExplain(f);
        if (deep != null) return deep;

        Map<String,Object> res = new HashMap<>();
        res.put("findingId", f.getFindingId());
        res.put("title", f.getTitle());
        res.put("summary", "Finding '" + f.getTitle() + "' pada asset '" + f.getAssetName() + "' dengan severity " + f.getSeverity() + " dan risk " + f.getRiskScore() + " (" + f.getRiskLevel() + ").");
        res.put("rootCause", rootCause(f));
        res.put("evidenceSummary", "Detected via " + f.getSource() + " at " + f.getFilePath() + ":" + f.getLineNumber() + ". Data flow: " + f.getDataFlow());
        res.put("impact", impact(f));
        res.put("remediation", remediation(f));
        res.put("codeFix", codeFix(f));
        res.put("testRecommendation", "Add unit test for authorization check + integration test for API endpoint + DAST regression.");
        res.put("priority", priority(f));
        res.put("isLikelyFalsePositive", "LOW".equals(f.getConfidence()) && f.getCvss()!=null && f.getCvss()<4);
        res.put("isLikelyDuplicate", false);
        res.put("aiProvider", deepseekKey != null && !deepseekKey.isBlank() ? "deepseek" : "rule-based (set DEEPSEEK_API_KEY for real LLM)");
        return res;
    }

    private Map<String,Object> tryDeepSeekExplain(Finding f) {
        if (deepseekKey == null || deepseekKey.isBlank() || deepseekKey.contains("change-me")) return null;
        try {
            String prompt = String.format("""
                You are senior AppSec engineer. Analyze finding:
                Title: %s
                Type: %s CWE: %s OWASP: %s
                Severity: %s Confidence: %s
                File: %s:%s Function: %s
                Code: %s
                DataFlow: %s
                Asset: %s Env: %s Exposed: %s Reachable: %s CVSS: %s KEV: %s
                Provide JSON with keys: rootCause, impact, remediation, codeFix, testRecommendation, isLikelyFalsePositive (bool), isLikelyDuplicate (bool)
                Respond ONLY JSON.
                """,
                f.getTitle(), f.getType(), f.getCwe(), f.getOwasp(), f.getSeverity(), f.getConfidence(),
                f.getFilePath(), f.getLineNumber(), f.getFunctionName(),
                f.getCodeSnippet()!=null? f.getCodeSnippet().substring(0, Math.min(800, f.getCodeSnippet().length())) : "",
                f.getDataFlow(), f.getAssetName(), f.getEnvironment(), f.getInternetExposed(), f.getReachable(), f.getCvss(), f.getKev());

            Map<String,Object> body = Map.of(
                "model", deepseekModel,
                "messages", List.of(
                    Map.of("role","system","content","You are AI Security Analyst for VulneraX. Return strict JSON."),
                    Map.of("role","user","content", prompt)
                ),
                "temperature", 0.2,
                "max_tokens", 1200
            );
            String jsonBody = om.writeValueAsString(body);
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(deepseekBase + "/chat/completions"))
                    .header("Content-Type","application/json")
                    .header("Authorization","Bearer " + deepseekKey)
                    .timeout(Duration.ofSeconds(20))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                log.warn("DeepSeek non-200: {} {}", resp.statusCode(), resp.body());
                return null;
            }
            JsonNode root = om.readTree(resp.body());
            String content = root.path("choices").path(0).path("message").path("content").asText();
            // try parse JSON from content
            JsonNode inner;
            try { inner = om.readTree(content); } catch (Exception e) {
                // extract JSON object
                int s = content.indexOf('{');
                int e2 = content.lastIndexOf('}');
                if (s!=-1 && e2!=-1) inner = om.readTree(content.substring(s, e2+1));
                else return null;
            }
            Map<String,Object> res = new HashMap<>();
            res.put("findingId", f.getFindingId());
            res.put("title", f.getTitle());
            res.put("summary", "DeepSeek analysis for " + f.getTitle());
            res.put("rootCause", inner.path("rootCause").asText(rootCause(f)));
            res.put("evidenceSummary", "Detected via " + f.getSource() + " at " + f.getFilePath() + ":" + f.getLineNumber());
            res.put("impact", inner.path("impact").asText(impact(f)));
            res.put("remediation", inner.path("remediation").asText(remediation(f)));
            res.put("codeFix", inner.path("codeFix").asText(codeFix(f)));
            res.put("testRecommendation", inner.path("testRecommendation").asText("Add regression test"));
            res.put("priority", priority(f));
            res.put("isLikelyFalsePositive", inner.path("isLikelyFalsePositive").asBoolean(false));
            res.put("isLikelyDuplicate", inner.path("isLikelyDuplicate").asBoolean(false));
            res.put("aiProvider", "deepseek:" + deepseekModel);
            res.put("rawDeepSeek", content);
            return res;
        } catch (Exception e) {
            log.warn("DeepSeek call failed, fallback to rule: {}", e.getMessage());
            return null;
        }
    }

    private String rootCause(Finding f) {
        if (f.getType()!=null && f.getType().contains("AUTHORIZATION")) return "Object-level authorization missing in " + f.getFunctionName() + ". Authentication present but ownership not validated before repository access.";
        if ("INJECTION".equals(f.getType())) return "Unsanitized input concatenated into query. Missing parameterized query / ORM usage.";
        if ("SECRET".equals(f.getType())) return "Hardcoded credential committed to repository. Secret not managed via Vault/KMS and exposed in build artifact.";
        if ("SCA".equals(f.getType())) return "Transitive vulnerable dependency. Direct dependency pulls vulnerable component, reachable from application code.";
        return "Insecure implementation of " + f.getType() + " with CWE " + f.getCwe() + ". Root cause is missing security control.";
    }
    private String impact(Finding f) {
        if (Boolean.TRUE.equals(f.getInternetExposed()) && "CRITICAL".equals(f.getBusinessCriticality())) return "Critical - Internet exposed + critical asset + sensitive data. Exploit would lead to data breach.";
        if (Boolean.TRUE.equals(f.getKev())) return "High - Known exploited in the wild (CISA KEV). Immediate patch required.";
        return "Risk level " + f.getRiskLevel() + " with CVSS " + f.getCvss() + ". Business impact depends on data classification.";
    }
    private String remediation(Finding f) {
        if (f.getType()!=null && f.getType().contains("AUTHORIZATION")) return "Implement object-level authorization: validate that authenticated user owns/is authorized for requested object id before DB access. Add service-layer check + tests.";
        if ("SECRET".equals(f.getType())) return "Rotate secret immediately, purge from git history, move to Vault/Secrets Manager, enable secret scanning in CI, add pre-commit hook.";
        if ("INJECTION".equals(f.getType())) return "Use parameterized queries / prepared statements, input validation, ORM, and WAF rule as compensating control.";
        return f.getRecommendation()!=null? f.getRecommendation(): "Follow secure coding standard for " + f.getType() + " and verify via retest.";
    }
    private String codeFix(Finding f) {
        if ("INJECTION".equals(f.getType())) return "// Before: String q = \"SELECT * FROM users WHERE id=\" + input;\n// After: PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\"); ps.setString(1, input);";
        if (f.getType()!=null && f.getType().contains("AUTHORIZATION")) return "// In Service:\nif (!account.getOwnerId().equals(currentUser.getId()) && !currentUser.hasRole(\"ADMIN\")) throw new AccessDeniedException();\nreturn repo.findById(id);";
        return "// Apply secure pattern for " + f.getType() + " per CWE " + f.getCwe();
    }
    private String priority(Finding f) {
        double r = f.getRiskScore()!=null? f.getRiskScore():0;
        if (r>=81) return "P0 - Fix within 24 hours (SLA breach if not)";
        if (r>=61) return "P1 - Fix within 7 days";
        if (r>=41) return "P2 - Fix within 30 days";
        return "P3 - Fix within 90 days";
    }

    public Map<String,Object> prioritize(UUID projectId) {
        List<Finding> list = projectId!=null? findingRepo.findByProjectId(projectId): findingRepo.findAll();
        list.sort(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())));
        List<Map<String,Object>> top = list.stream().limit(10).map(f -> Map.<String,Object>of(
            "id", f.getId(),
            "findingId", f.getFindingId(),
            "title", f.getTitle(),
            "risk", f.getRiskScore()!=null? f.getRiskScore():0,
            "severity", f.getSeverity(),
            "asset", f.getAssetName()!=null?f.getAssetName():"unknown",
            "reason", "Risk " + f.getRiskScore() + " due to CVSS " + f.getCvss() + (Boolean.TRUE.equals(f.getKev())?" + KEV":"") + (Boolean.TRUE.equals(f.getInternetExposed())?" + exposed":"")
        )).toList();
        return Map.of("total", list.size(), "prioritized", top);
    }

    public Map<String,Object> reportDraft(UUID projectId, String type) {
        // mock AI generated report sections
        return Map.of(
            "type", type!=null?type:"EXECUTIVE",
            "executiveSummary", "Security assessment identified contextual risks driven by internet-exposed critical assets and vulnerable dependencies. Top 3 risks require immediate remediation.",
            "keyFindings", prioritize(projectId).get("prioritized"),
            "recommendations", List.of("Patch KEV dependencies within 24h", "Fix BOLA on payment API", "Rotate hardcoded secrets and enable Vault"),
            "generatedBy", "AI Security Analyst"
        );
    }
}
