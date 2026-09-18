package com.vulnerax.modules.finding;

import com.vulnerax.modules.audit.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EvidenceServiceTest {

    @Mock EvidenceRepository evidenceRepo;
    @Mock AuditService auditService;
    @InjectMocks EvidenceService service;

    private Evidence ev;

    @BeforeEach
    void setUp() {
        ev = Evidence.builder().findingId(UUID.randomUUID()).type("CODE_SNIPPET")
                .content("a.java:1\ncode").build();
        ev.setId(UUID.randomUUID());
        lenient().when(evidenceRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void getByFinding_and_count() {
        UUID fid = UUID.randomUUID();
        when(evidenceRepo.findByFindingId(fid)).thenReturn(List.of(ev));
        assertThat(service.getByFinding(fid)).hasSize(1);
        when(evidenceRepo.countValidated()).thenReturn(7L);
        assertThat(service.getValidatedCount()).isEqualTo(7L);
    }

    @Test
    void create_computesSha_whenMissing() {
        Evidence in = Evidence.builder().findingId(UUID.randomUUID()).type("T").content("hello").build();
        in.setId(UUID.randomUUID());
        Evidence out = service.create(in);
        assertThat(out.getSha256()).hasSize(64);
        verify(auditService).log(eq("EVIDENCE_CREATED"), eq("Evidence"), anyString(), anyString());
    }

    @Test
    void create_keepsExistingSha() {
        Evidence in = Evidence.builder().findingId(UUID.randomUUID()).type("T").content("hello").sha256("abc").build();
        in.setId(UUID.randomUUID());
        assertThat(service.create(in).getSha256()).isEqualTo("abc");
    }

    @Test
    void validate_marksValidated() {
        UUID id = UUID.randomUUID();
        when(evidenceRepo.findById(id)).thenReturn(Optional.of(ev));
        Evidence out = service.validate(id, "hash1");
        assertThat(out.isValidated()).isTrue();
        assertThat(out.getValidationHash()).isEqualTo("hash1");
        verify(auditService).log(eq("EVIDENCE_VALIDATED"), anyString(), anyString(), anyString());
    }

    @Test
    void validate_missing_throws() {
        when(evidenceRepo.findById(any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.validate(UUID.randomUUID(), "h")).isInstanceOf(RuntimeException.class);
    }

    @Test
    void createHttp_truncatesBody_and_hashes() {
        UUID fid = UUID.randomUUID();
        String big = "x".repeat(6000);
        Evidence out = service.createHttpEvidence(fid, "GET", "https://example.com", 200, "h", big, "p", 120L);
        assertThat(out.getResponseBody()).hasSize(5000);
        assertThat(out.getSha256()).hasSize(64);
        Evidence out2 = service.createHttpEvidence(fid, "GET", "https://example.com", 200, "h", null, null, 5L);
        assertThat(out2.getResponseBody()).isEqualTo("");
    }

    @Test
    void createCode_buildsContent() {
        Evidence out = service.createCodeEvidence(UUID.randomUUID(), "a.java", 10, "code()", "sast");
        assertThat(out.getContent()).contains("a.java:10");
        assertThat(out.getSha256()).hasSize(64);
    }
}
