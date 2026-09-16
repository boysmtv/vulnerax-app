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

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DataSeederTest {

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
        // Clear demo flag to ensure default seeding path
        System.clearProperty("VULNERAX_SEED_DEMO");
    }

    @Test
    void run_whenDataExists_noOp() {
        when(userRepo.count()).thenReturn(5L);
        seeder.run();
        verify(userRepo, never()).save(any());
    }

    @Test
    void run_whenEmpty_createsAdmin() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        User saved = User.builder().email("admin@vulnerax.io").role(User.Role.ORG_OWNER).build();
        when(userRepo.save(any(User.class))).thenReturn(saved);

        seeder.run();

        verify(userRepo).save(any(User.class));
        verify(encoder).encode("Admin12345!abc");
    }

    @Test
    void run_whenEmpty_savesAdminWithCorrectFields() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        seeder.run();

        verify(userRepo).save(argThat(user ->
                user.getEmail().equals("admin@vulnerax.io") &&
                user.getFullName().equals("Security Admin") &&
                user.getRole() == User.Role.ORG_OWNER
        ));
    }

    @Test
    void run_doesNotCreateMockAssets() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenReturn(User.builder().build());

        seeder.run();

        verify(assetRepo, never()).save(any());
    }

    @Test
    void run_doesNotCreateOrganizations() {
        when(userRepo.count()).thenReturn(0L);
        when(encoder.encode("Admin12345!abc")).thenReturn("$2a$10$hashed");
        when(userRepo.save(any(User.class))).thenReturn(User.builder().build());

        seeder.run();

        verify(orgRepo, never()).save(any());
    }
}
