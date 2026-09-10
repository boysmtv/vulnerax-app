package com.vulnerax.modules.ai;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/ai")
@RequiredArgsConstructor
public class AiController {
    private final AiAnalystService svc;
    @GetMapping("/explain/{findingId}")
    public ApiResponse<?> explain(@PathVariable UUID findingId) { return ApiResponse.ok(svc.explain(findingId)); }
    @GetMapping("/prioritize")
    public ApiResponse<?> prioritize(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(svc.prioritize(projectId)); }
    @GetMapping("/report-draft")
    public ApiResponse<?> reportDraft(@RequestParam(required = false) UUID projectId, @RequestParam(required = false) String type) { return ApiResponse.ok(svc.reportDraft(projectId, type)); }
}
