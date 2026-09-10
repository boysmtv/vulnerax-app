package com.vulnerax.modules.mobile;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/mobile") @RequiredArgsConstructor
public class MobileController {
    private final MobileService svc;
    @PostMapping("/upload")
    public ApiResponse<?> upload(@RequestParam UUID projectId, @RequestParam String fileName, @RequestParam(required = false) String platform,
                                 @RequestParam(value = "file", required = false) MultipartFile file) {
        return ApiResponse.ok(svc.upload(projectId, fileName, platform, file));
    }
    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(svc.get(id)); }
    @GetMapping("/{id}/workspace")
    public ApiResponse<?> workspace(@PathVariable UUID id) { return ApiResponse.ok(svc.workspace(id)); }
}
