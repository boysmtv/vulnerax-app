package com.vulnerax.modules.dashboard;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/dashboard")
@RequiredArgsConstructor
public class DashboardController {
    private final DashboardService svc;
    @GetMapping("/posture")
    public ApiResponse<?> posture(@RequestParam(required = false) UUID projectId, @RequestParam(required = false) UUID organizationId) {
        return ApiResponse.ok(svc.securityPosture(projectId, organizationId));
    }
    @GetMapping("/application/{projectId}")
    public ApiResponse<?> appDash(@PathVariable UUID projectId) { return ApiResponse.ok(svc.applicationDashboard(projectId)); }
}
