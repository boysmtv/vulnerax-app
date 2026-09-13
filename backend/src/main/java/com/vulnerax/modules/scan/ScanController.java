package com.vulnerax.modules.scan;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import com.vulnerax.modules.rbac.RequirePermission;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
public class ScanController {
    private final ScanService service;

    @GetMapping
    @RequirePermission("SCANS_READ")
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId, Pageable p) {
        return ApiResponse.ok(PageResponse.from(service.list(projectId, p)));
    }

    @GetMapping("/{id}")
    @RequirePermission("SCANS_READ")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(service.get(id)); }

    @GetMapping("/{id}/jobs")
    @RequirePermission("SCANS_READ")
    public ApiResponse<?> jobs(@PathVariable UUID id) { return ApiResponse.ok(service.jobs(id)); }

    @PostMapping
    @RequirePermission("SCANS_WRITE")
    public ApiResponse<?> create(@RequestBody Scan s, Authentication auth) {
        return ApiResponse.ok(service.create(s, auth != null ? auth.getName() : "system"));
    }

    @PostMapping(value = "/upload", consumes = {"multipart/form-data"})
    @RequirePermission("SCANS_WRITE")
    public ApiResponse<?> upload(@RequestParam UUID projectId,
                                 @RequestParam String scannerType,
                                 @RequestParam(required = false) String profile,
                                 @RequestParam(required = false) UUID assetId,
                                 @RequestParam("file") MultipartFile file,
                                 Authentication auth) throws Exception {
        String content = new String(file.getBytes(), StandardCharsets.UTF_8);
        String escaped = content.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
        String cfg = "{\"fileName\":\"" + file.getOriginalFilename() + "\",\"fileContent\":\"" + escaped + "\"}";
        Scan s = Scan.builder()
                .projectId(projectId)
                .assetId(assetId)
                .scannerType(scannerType)
                .profile(profile != null ? profile : "STANDARD")
                .target(file.getOriginalFilename())
                .configJson(cfg)
                .build();
        return ApiResponse.ok(service.create(s, auth != null ? auth.getName() : "system"));
    }

    @PostMapping("/{id}/cancel")
    @RequirePermission("SCANS_CANCEL")
    public ApiResponse<?> cancel(@PathVariable UUID id) { service.cancel(id); return ApiResponse.ok(null, "Cancelled"); }
}
