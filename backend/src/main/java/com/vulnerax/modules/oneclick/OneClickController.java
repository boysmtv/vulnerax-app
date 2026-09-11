package com.vulnerax.modules.oneclick;

import com.vulnerax.common.ApiResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/one-click")
@RequiredArgsConstructor
public class OneClickController {
    private final OneClickService svc;

    @PostMapping("/test")
    public ApiResponse<?> test(@RequestBody Req req) {
        var run = svc.start(req.getTarget(), req.getProjectId());
        return ApiResponse.ok(Map.of(
                "id", run.getId(),
                "target", run.getTarget(),
                "detectedType", run.getDetectedType(),
                "status", run.getStatus(),
                "progress", run.getProgress(),
                "totalScans", run.getTotalScans(),
                "message", run.getMessage()
        ));
    }

    @GetMapping("/{id}/progress")
    public ApiResponse<?> progress(@PathVariable UUID id) {
        return ApiResponse.ok(svc.progress(id));
    }

    @GetMapping("/{id}/report")
    public ApiResponse<?> report(@PathVariable UUID id) {
        var p = svc.progress(id);
        UUID reportId = (UUID) p.get("reportId");
        if (reportId == null) return ApiResponse.fail("Report not ready yet — progress " + p.get("progress") + "% status " + p.get("status"));
        return ApiResponse.ok(Map.of("reportId", reportId, "runId", id));
    }

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId) {
        return ApiResponse.ok(svc.list(projectId));
    }

    @Data
    public static class Req {
        private String target; // repo url, domain, image, apk path, api url
        private UUID projectId; // optional, auto-pick first if null
    }
}
