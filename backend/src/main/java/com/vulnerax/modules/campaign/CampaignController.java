package com.vulnerax.modules.campaign;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/campaigns") @RequiredArgsConstructor
public class CampaignController {
    private final CampaignService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody SecurityCampaign c){ return ApiResponse.ok(svc.create(c)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID organizationId){ return ApiResponse.ok(svc.list(organizationId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
