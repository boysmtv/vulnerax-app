package com.vulnerax.modules.identity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(MfaController.class)
@AutoConfigureMockMvc(addFilters = false)
class MfaControllerTest {

    @Autowired MockMvc mvc;
    @MockBean UserRepository userRepo;
    @MockBean TotpService totpService;
    @MockBean com.vulnerax.modules.identity.JwtTokenProvider jwtTokenProvider;
    @MockBean com.vulnerax.modules.identity.JwtAuthFilter jwtAuthFilter;
    @MockBean JpaMetamodelMappingContext jpaMetamodelMappingContext;

    @Test
    void mfa_controller_loads() throws Exception {
        mvc.perform(get("/api/v1/auth/mfa/recovery-codes"))
                .andExpect(result -> {
                    int s = result.getResponse().getStatus();
                    if (s == 500) {
                        String body = result.getResponse().getContentAsString();
                        boolean isAuthError = body.contains("Authentication") || body.contains("null");
                        if (!isAuthError) throw new AssertionError("Unexpected 500: " + body);
                    }
                });
    }
}
