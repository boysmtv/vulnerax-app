package com.vulnerax.modules.assessment;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/assessments")
@RequiredArgsConstructor
public class AssessmentController {
    private final AssetRepository assetRepo;
    private final ScanService scanService;

    @PostMapping("/project/{projectId}")
    public ApiResponse<?> runProjectAssessment(@PathVariable UUID projectId,
                                               @RequestParam(defaultValue = "STANDARD") String profile) {
        List<Asset> assets = assetRepo.findByProjectId(projectId);
        if (assets.isEmpty()) {
            return ApiResponse.fail("No assets in project. Add BE, FE, Android assets first.");
        }
        List<Map<String,Object>> created = new ArrayList<>();
        for (Asset a : assets) {
            String scannerType = switch (a.getType()) {
                case "REPOSITORY", "PACKAGE" -> "SCA";
                case "WEBAPP", "DOMAIN", "URL" -> "DAST";
                case "API" -> "API";
                case "MOBILE_APP" -> "MOBILE";
                case "CONTAINER_IMAGE" -> "CONTAINER";
                case "K8S_CLUSTER" -> "K8S";
                case "DATABASE" -> "SAST";
                default -> "SAST";
            };
            // For BE repo, run 3 scanners: SAST, SCA, SECRET
            List<String> types = new ArrayList<>();
            if ("REPOSITORY".equals(a.getType())) types = List.of("SAST","SCA","SECRET");
            else if ("MOBILE_APP".equals(a.getType())) types = List.of("MOBILE","SECRET");
            else if ("API".equals(a.getType())) types = List.of("API","DAST","SAST");
            else types = List.of(scannerType);

            for (String t : types) {
                Scan s = Scan.builder()
                        .projectId(projectId)
                        .assetId(a.getId())
                        .scannerType(t)
                        .profile(profile)
                        .target(a.getName() + " (" + a.getIdentifier() + ")")
                        .configJson("{\"assetType\":\""+a.getType()+"\",\"technology\":\""+a.getTechnology()+"\"}")
                        .build();
                Scan saved = scanService.create(s, "assessment-orchestrator");
                created.add(Map.of("asset", a.getName(), "type", a.getType(), "scanner", t, "scanId", saved.getId()));
            }
        }
        return ApiResponse.ok(Map.of(
            "projectId", projectId,
            "assets", assets.size(),
            "scansCreated", created.size(),
            "scans", created,
            "message", "Unified assessment started - all scanners (SAST/SCA/Secret/DAST/API/Mobile) running in parallel via Kafka orchestrator. Findings will appear in Vulnerability Explorer & Dashboard."
        ));
    }

    @GetMapping("/project/{projectId}/summary")
    public ApiResponse<?> summary(@PathVariable UUID projectId) {
        // quick summary: assets count, scans, findings would be fetched via other services but we return mock here
        List<Asset> assets = assetRepo.findByProjectId(projectId);
        return ApiResponse.ok(Map.of(
            "projectId", projectId,
            "assets", assets.stream().map(a -> Map.of("name", a.getName(), "type", a.getType(), "tech", a.getTechnology(), "exposed", a.getInternetExposed())).toList(),
            "totalAssets", assets.size()
        ));
    }
}
