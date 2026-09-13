package com.vulnerax.modules.oneclick;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanService;
import com.vulnerax.modules.scan.SecurityCoverageRegistry;
import com.vulnerax.modules.asset.AssetService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/oneclick")
@RequiredArgsConstructor
public class OneClickController {
    private final ScanService scanService;
    private final AssetService assetService;
    private final SecurityCoverageRegistry coverageRegistry;

    @PostMapping("/scan")
    public ApiResponse<?> scan(@RequestParam String targetType, @RequestParam String targetUrl, Authentication auth) {
        String userId = auth.getName();

        // 1. Detect capabilities
        List<String> capabilities = detectCapabilities(targetType);

        // 2. Plan coverage
        Map<String, Object> coverage = coverageRegistry.planCoverage(targetType, targetUrl);

        // 3. Select scanners based on target type
        List<String> scanners = selectScanners(targetType, capabilities);

        // 4. Create asset
        var asset = assetService.createAsset(targetUrl, targetType, userId);

        // 5. Create scan with coverage info
        var scan = scanService.createScan(targetUrl, userId);
        scan.setScannerType(String.join(",", scanners));
        scan.setScanType(targetType);
        scanService.startScan(scan, userId);

        return ApiResponse.ok(Map.of(
                "scanId", scan.getId(),
                "assetId", asset.getId(),
                "targetType", targetType,
                "detectedCapabilities", capabilities,
                "coveragePlan", coverage,
                "scannersToRun", scanners,
                "estimatedTests", coverage.get("totalTests"),
                "message", "Smart scan initiated with " + scanners.size() + " scanners"
        ));
    }

    @GetMapping("/plan")
    public ApiResponse<?> plan(@RequestParam String targetType, @RequestParam String targetUrl) {
        List<String> capabilities = detectCapabilities(targetType);
        Map<String, Object> coverage = coverageRegistry.planCoverage(targetType, targetUrl);
        List<String> scanners = selectScanners(targetType, capabilities);

        return ApiResponse.ok(Map.of(
                "targetType", targetType,
                "capabilities", capabilities,
                "recommendedScanners", scanners,
                "coverage", coverage
        ));
    }

    private List<String> detectCapabilities(String targetType) {
        return switch (targetType.toLowerCase()) {
            case "url" -> List.of("or", "url", "sqli", "xss", "auth");
            case "ip" -> List.of("ip", "origin");
            case "domain" -> List.of("domain", "or", "tls");
            case "mobile" -> List.of("mobile", "api");
            default -> List.of("or", "url");
        };
    }

    private List<String> selectScanners(String targetType, List<String> capabilities) {
        Set<String> scanners = new LinkedHashSet<>();
        if (capabilities.contains("sqli") || capabilities.contains("xss") || capabilities.contains("lfi") || capabilities.contains("auth")) {
            scanners.add("DAST");
        }
        if (capabilities.contains("or") || capabilities.contains("url")) {
            scanners.add("SAST");
        }
        if (capabilities.contains("tls")) {
            scanners.add("DAST");
        }
        if (scanners.isEmpty()) {
            scanners.add("DAST");
        }
        return List.copyOf(scanners);
    }
}
