package com.vulnerax.modules.audit;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {
    private final AuditService service;
    @GetMapping
    public ApiResponse<?> list(Pageable p) { return ApiResponse.ok(PageResponse.from(service.list(p))); }
}
