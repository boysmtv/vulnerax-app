package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EvidenceServiceAdditionalTest {

    @Mock EvidenceRepository evidenceRepo;
    @Mock com.vulnerax.modules.audit.AuditService auditService;
    @InjectMocks EvidenceService service;

    @Test
    void getByFinding_returnsEvidence() {
        UUID findingId = UUID.randomUUID();
        Evidence e = Evidence.builder()
                .findingId(findingId).type("SCREENSHOT").content("data").build();
        when(evidenceRepo.findByFindingId(findingId)).thenReturn(List.of(e));
        List<Evidence> result = service.getByFinding(findingId);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getType()).isEqualTo("SCREENSHOT");
    }

    @Test
    void getByFinding_emptyList() {
        UUID findingId = UUID.randomUUID();
        when(evidenceRepo.findByFindingId(findingId)).thenReturn(List.of());
        List<Evidence> result = service.getByFinding(findingId);
        assertThat(result).isEmpty();
    }

    @Test
    void getValidatedCount_returnsCount() {
        when(evidenceRepo.countValidated()).thenReturn(5L);
        long count = service.getValidatedCount();
        assertThat(count).isEqualTo(5L);
    }

    @Test
    void create_savesEvidence() {
        UUID evId = UUID.randomUUID();
        Evidence e = Evidence.builder()
                .findingId(UUID.randomUUID()).type("LOG").content("log data").build();
        when(evidenceRepo.save(any())).thenAnswer(inv -> {
            Evidence ev = inv.getArgument(0);
            ev.setId(evId);
            return ev;
        });
        Evidence result = service.create(e);
        assertThat(result).isNotNull();
        verify(evidenceRepo).save(e);
        verify(auditService).log(eq("EVIDENCE_CREATED"), anyString(), anyString(), anyString());
    }

    @Test
    void create_withSha256_doesNotComputeHash() {
        UUID evId = UUID.randomUUID();
        Evidence e = Evidence.builder()
                .findingId(UUID.randomUUID()).type("LOG").content("data").sha256("existing-hash").build();
        when(evidenceRepo.save(any())).thenAnswer(inv -> {
            Evidence ev = inv.getArgument(0);
            ev.setId(evId);
            return ev;
        });
        Evidence result = service.create(e);
        assertThat(result.getSha256()).isEqualTo("existing-hash");
    }

    @Test
    void validate_setsValidatedTrue() {
        UUID evId = UUID.randomUUID();
        Evidence e = Evidence.builder().findingId(UUID.randomUUID()).type("LOG").build();
        e.setId(evId);
        when(evidenceRepo.findById(evId)).thenReturn(java.util.Optional.of(e));
        when(evidenceRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Evidence result = service.validate(evId, "validation-hash-123");
        assertThat(result.isValidated()).isTrue();
        assertThat(result.getValidationHash()).isEqualTo("validation-hash-123");
    }

    @Test
    void createHttpEvidence_savesHttpEvidence() {
        UUID findingId = UUID.randomUUID();
        when(evidenceRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Evidence result = service.createHttpEvidence(findingId, "POST", "https://api.test.com/login",
                200, "Content-Type: json", "{\"token\":\"x\"}", "payload", 150L);
        assertThat(result.getType()).isEqualTo("HTTP_REQUEST");
        assertThat(result.getRequestMethod()).isEqualTo("POST");
        assertThat(result.getRequestUrl()).isEqualTo("https://api.test.com/login");
        assertThat(result.getResponseStatusCode()).isEqualTo(200);
        assertThat(result.getAuthor()).isEqualTo("dast-analyzer");
    }

    @Test
    void createCodeEvidence_savesCodeEvidence() {
        UUID findingId = UUID.randomUUID();
        when(evidenceRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Evidence result = service.createCodeEvidence(findingId, "src/main.java", 42, "stmt.execute(sql)", "semgrep");
        assertThat(result.getType()).isEqualTo("CODE_SNIPPET");
        assertThat(result.getRequestUrl()).isEqualTo("src/main.java");
        assertThat(result.getAuthor()).isEqualTo("semgrep");
        assertThat(result.getContent()).contains("src/main.java:42");
    }
}
