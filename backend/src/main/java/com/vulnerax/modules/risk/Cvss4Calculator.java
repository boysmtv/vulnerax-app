package com.vulnerax.modules.risk;

import java.util.LinkedHashMap;
import java.util.Map;

public class Cvss4Calculator {

    public record CvssResult(double score, String severity, String vector, String version, String source) {}

    public static CvssResult calculate(String cwe, String attackVector, String privileges,
                                        boolean internetExposed, boolean kev, boolean dataBreach) {
        if (cwe == null) return null;

        double score = 0;
        Map<String, String> metrics = new LinkedHashMap<>();

        // Base metrics
        String av = attackVector != null ? attackVector : (internetExposed ? "N" : "L");
        metrics.put("AV", av);
        metrics.put("AC", "L");
        metrics.put("AT", "N");
        metrics.put("PR", privileges != null ? privileges : "L");
        metrics.put("UI", "N");

        // Base score components
        score += switch (av) {
            case "N" -> 8.5;
            case "A" -> 6.5;
            case "L" -> 5.0;
            case "P" -> 2.0;
            default -> 5.0;
        };

        // Threat metrics
        metrics.put("V", kev ? "A" : "D");
        if (kev) score += 5.0;

        metrics.put("RE", dataBreach ? "A" : "U");
        if (dataBreach) score += 3.0;

        // Environmental (simplified)
        metrics.put("CR", "H");
        metrics.put("IR", "H");
        metrics.put("AR", "H");

        // Cap score at 10
        score = Math.min(10, score);

        String severity = switch ((int) score) {
            case 9, 10 -> "CRITICAL";
            case 7, 8 -> "HIGH";
            case 4, 5, 6 -> "MEDIUM";
            case 2, 3 -> "LOW";
            default -> "NONE";
        };

        StringBuilder vectorStr = new StringBuilder("CVSS:4.0");
        metrics.forEach((k, v) -> vectorStr.append("/").append(k).append(":").append(v));

        return new CvssResult(score, severity, vectorStr.toString(), "4.0", "CALCULATED");
    }

    public static String getSeverity(double score) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        if (score > 0) return "LOW";
        return "NONE";
    }
}
