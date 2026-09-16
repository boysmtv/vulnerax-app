package com.vulnerax.seed;

import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.User;
import com.vulnerax.modules.identity.UserRepository;
import com.vulnerax.modules.organization.OrganizationRepository;
import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.organization.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DataSeederAdditionalTest {

    @Mock UserRepository userRepo;
    @Mock OrganizationRepository orgRepo;
    @Mock WorkspaceRepository wsRepo;
    @Mock ProjectRepository projRepo;
    @Mock AssetRepository assetRepo;
    @Mock FindingService findingService;
    @Mock PasswordEncoder encoder;
    @InjectMocks DataSeeder seeder;

    @BeforeEach
    void setUp() {
        System.clearProperty("VULNERAX_SEED_DEMO");
    }

    @Test
    void run_whenDataExists_doesNotSave() {
        when(userRepo.count()).thenReturn(10L);
        seeder.run();
        verify(userRepo, never()).save(any());
        verify(encoder, never()).encode(any());
    }

    @Test
    void run_whenEmpty_createsAdminWithCorrectRole() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        seeder.run();
        verify(userRepo).save(argThat(u ->
                u.getEmail().equals("admin@vulnerax.io") &&
                u.getFullName().equals("Security Admin") &&
                u.getRole() == User.Role.ORG_OWNER
        ));
    }

    @Test
    void run_doesNotCreateOrgsOrProjects() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenReturn(User.builder().build());
        seeder.run();
        verify(orgRepo, never()).save(any());
        verify(wsRepo, never()).save(any());
        verify(projRepo, never()).save(any());
        verify(assetRepo, never()).save(any());
    }

    @Test
    void run_doesNotCreateFindings() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenReturn(User.builder().build());
        seeder.run();
        verify(findingService, never()).create(any());
    }

    @Test
    void run_multipleCalls_onlySeedsOnce() {
        when(userRepo.count()).thenReturn(0L).thenReturn(1L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenReturn(User.builder().build());
        seeder.run();
        seeder.run();
        verify(userRepo, times(1)).save(any());
    }
}
