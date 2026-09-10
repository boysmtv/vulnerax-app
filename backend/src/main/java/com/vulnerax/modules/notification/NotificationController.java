package com.vulnerax.modules.notification;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/notifications") @RequiredArgsConstructor
public class NotificationController {
    private final NotificationService svc;
    @PostMapping public ApiResponse<?> send(@RequestBody Notification n){ return ApiResponse.ok(svc.send(n)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
