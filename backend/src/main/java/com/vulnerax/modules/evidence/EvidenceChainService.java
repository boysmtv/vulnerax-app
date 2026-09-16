package com.vulnerax.modules.evidence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service("evidenceChainService")
@RequiredArgsConstructor
public class EvidenceChainService {
    private final EvidenceChainRepository repo;

    public EvidenceChain record(UUID findingId, UUID scanId, String type, String status, String description) {
        EvidenceChain e = EvidenceChain.builder()
                .findingId(findingId)
                .scanId(scanId)
                .evidenceType(type)
                .status(status)
                .description(description)
                .attempts(1)
                .build();
        return repo.save(e);
    }

    public EvidenceChain recordDns(UUID findingId, UUID scanId, boolean resolved, String addresses) {
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("DNS_RESOLUTION")
                .status(resolved ? "CONFIRMED" : "REFUTED")
                .dnsEvidence("{\"resolved\":" + resolved + ",\"addresses\":\"" + addresses + "\"}")
                .description("DNS " + (resolved ? "resolved to " + addresses : "failed to resolve"))
                .detectionConfidence(resolved ? 1.0 : 0.0)
                .evidenceStrength(resolved ? "CONFIRMED" : "NONE")
                .build());
    }

    public EvidenceChain recordTcp(UUID findingId, UUID scanId, boolean connected, int port, String error) {
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("TCP_CONNECTIVITY")
                .status(connected ? "CONFIRMED" : "REFUTED")
                .tcpEvidence("{\"port\":" + port + ",\"connected\":" + connected + ",\"error\":\"" + error + "\"}")
                .description("TCP port " + port + " " + (connected ? "connected" : "failed: " + error))
                .detectionConfidence(connected ? 1.0 : 0.0)
                .evidenceStrength(connected ? "CONFIRMED" : "NONE")
                .build());
    }

    public EvidenceChain recordHttp(UUID findingId, UUID scanId, int statusCode, String headers, String bodySnippet) {
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("HTTP_RESPONSE")
                .status(statusCode > 0 && statusCode < 500 ? "CONFIRMED" : "REFUTED")
                .httpEvidence("{\"statusCode\":" + statusCode + ",\"headers\":\"" + escape(headers) + "\"}")
                .description("HTTP response: " + statusCode)
                .detectionConfidence(statusCode > 0 ? 1.0 : 0.0)
                .evidenceStrength(statusCode > 0 ? "CONFIRMED" : "NONE")
                .build());
    }

    public EvidenceChain recordPayload(UUID findingId, UUID scanId, String payload, int responseCode, String responseSnippet, boolean matched) {
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("PAYLOAD_INJECTION")
                .status(matched ? "CONFIRMED" : "REFUTED")
                .payloadEvidence("{\"payload\":\"" + escape(payload) + "\",\"responseCode\":" + responseCode + ",\"matched\":" + matched + "}")
                .description("Payload injection " + (matched ? "produced expected response" : "no match"))
                .vulnerabilityConfidence(matched ? 0.8 : 0.0)
                .evidenceStrength(matched ? "STRONG" : "WEAK")
                .build());
    }

    public EvidenceChain recordComparison(UUID findingId, UUID scanId, String baseline, String test, boolean different) {
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("RESPONSE_COMPARISON")
                .status(different ? "CONFIRMED" : "REFUTED")
                .comparisonEvidence("{\"baseline\":" + baseline + ",\"test\":" + test + ",\"different\":" + different + "}")
                .description("Response comparison: " + (different ? "behavior changed" : "no difference"))
                .vulnerabilityConfidence(different ? 0.7 : 0.1)
                .evidenceStrength(different ? "MODERATE" : "WEAK")
                .build());
    }

    public EvidenceChain recordReproduction(UUID findingId, UUID scanId, int successes, int attempts) {
        double confidence = attempts > 0 ? (double) successes / attempts : 0;
        String strength = confidence >= 0.8 ? "CONFIRMED" : confidence >= 0.5 ? "STRONG" : confidence > 0 ? "MODERATE" : "NONE";
        return repo.save(EvidenceChain.builder()
                .findingId(findingId).scanId(scanId)
                .evidenceType("REPRODUCTION_ATTEMPT")
                .status(successes > 0 ? "CONFIRMED" : "REFUTED")
                .description("Reproduced " + successes + "/" + attempts + " attempts")
                .attempts(attempts)
                .vulnerabilityConfidence(confidence)
                .evidenceStrength(strength)
                .build());
    }

    public Map<String, Object> getEvidenceSummary(UUID findingId) {
        List<EvidenceChain> all = repo.findByFindingIdOrderByCreatedAtDesc(findingId);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalEvidence", all.size());
        summary.put("confirmedCount", all.stream().filter(e -> "CONFIRMED".equals(e.getStatus())).count());
        summary.put("refutedCount", all.stream().filter(e -> "REFUTED".equals(e.getStatus())).count());

        // Overall confidence
        double maxVulnConf = all.stream()
                .mapToDouble(e -> e.getVulnerabilityConfidence() != null ? e.getVulnerabilityConfidence() : 0)
                .max().orElse(0);
        summary.put("vulnerabilityConfidence", maxVulnConf);

        // Overall strength
        String strongest = all.stream()
                .map(EvidenceChain::getEvidenceStrength)
                .filter(Objects::nonNull)
                .max(Comparator.comparingInt(e -> switch (e) {
                    case "CONFIRMED" -> 5;
                    case "STRONG" -> 4;
                    case "MODERATE" -> 3;
                    case "WEAK" -> 2;
                    default -> 1;
                }))
                .orElse("NONE");
        summary.put("evidenceStrength", strongest);

        summary.put("evidence", all.stream().map(e -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", e.getId());
            item.put("type", e.getEvidenceType());
            item.put("status", e.getStatus());
            item.put("description", e.getDescription());
            item.put("strength", e.getEvidenceStrength());
            item.put("timestamp", e.getTimestamp());
            return item;
        }).toList());

        return summary;
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\"", "\\\"").replace("\n", " ");
    }
}
