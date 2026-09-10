package com.vulnerax.modules.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface AuditRepository extends JpaRepository<AuditEvent, UUID> {
    Page<AuditEvent> findByEntityType(String type, Pageable p);
}
