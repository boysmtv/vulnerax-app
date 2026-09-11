package com.vulnerax;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class VulneraxApplicationTest {
    @Test
    void contextLoads() {
        // return flow — application starts with H2 test profile
    }
}
