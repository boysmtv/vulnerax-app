package com.vulnerax.modules.audit;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditService {
    private final AuditRepository repo;

    public void log(String action, String entityType, String entityId, String details) {
        String actor = "system";
        try { var a = SecurityContextHolder.getContext().getAuthentication(); if (a!=null) actor = a.getName(); } catch (Exception e) {}
        AuditEvent ev = AuditEvent.builder().action(action).entityType(entityType).entityId(entityId).actor(actor).details(details).build();
        repo.save(ev);
    }
    public Page<AuditEvent> list(Pageable p) { return repo.findAll(p); }
}
