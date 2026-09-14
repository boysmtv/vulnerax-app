package com.vulnerax.modules.identity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerDtoTest {

    @Test
    void loginReq_noArgsConstructor() {
        AuthController.LoginReq lr = new AuthController.LoginReq();
        assertThat(lr).isNotNull();
        assertThat(lr.getEmail()).isNull();
        assertThat(lr.getPassword()).isNull();
    }

    @Test
    void loginReq_settersAndGetters() {
        AuthController.LoginReq lr = new AuthController.LoginReq();
        lr.setEmail("admin@vulnerax.io");
        lr.setPassword("secret123");
        assertThat(lr.getEmail()).isEqualTo("admin@vulnerax.io");
        assertThat(lr.getPassword()).isEqualTo("secret123");
    }

    @Test
    void loginReq_equals_sameValues() {
        AuthController.LoginReq lr1 = new AuthController.LoginReq();
        lr1.setEmail("a@b.com");
        lr1.setPassword("pass");
        AuthController.LoginReq lr2 = new AuthController.LoginReq();
        lr2.setEmail("a@b.com");
        lr2.setPassword("pass");
        assertThat(lr1).isEqualTo(lr2);
        assertThat(lr1.hashCode()).isEqualTo(lr2.hashCode());
    }

    @Test
    void loginReq_equals_differentEmail() {
        AuthController.LoginReq lr1 = new AuthController.LoginReq();
        lr1.setEmail("a@b.com");
        lr1.setPassword("pass");
        AuthController.LoginReq lr2 = new AuthController.LoginReq();
        lr2.setEmail("x@y.com");
        lr2.setPassword("pass");
        assertThat(lr1).isNotEqualTo(lr2);
    }

    @Test
    void loginReq_toString() {
        AuthController.LoginReq lr = new AuthController.LoginReq();
        lr.setEmail("test@test.com");
        lr.setPassword("p");
        String str = lr.toString();
        assertThat(str).contains("test@test.com");
    }

    @Test
    void registerReq_noArgsConstructor() {
        AuthController.RegisterReq rr = new AuthController.RegisterReq();
        assertThat(rr).isNotNull();
        assertThat(rr.getEmail()).isNull();
        assertThat(rr.getPassword()).isNull();
        assertThat(rr.getFullName()).isNull();
        assertThat(rr.getRole()).isNull();
    }

    @Test
    void registerReq_settersAndGetters() {
        AuthController.RegisterReq rr = new AuthController.RegisterReq();
        rr.setEmail("user@vulnerax.io");
        rr.setPassword("pass123");
        rr.setFullName("Test User");
        rr.setRole("SECURITY_ADMIN");
        assertThat(rr.getEmail()).isEqualTo("user@vulnerax.io");
        assertThat(rr.getPassword()).isEqualTo("pass123");
        assertThat(rr.getFullName()).isEqualTo("Test User");
        assertThat(rr.getRole()).isEqualTo("SECURITY_ADMIN");
    }

    @Test
    void registerReq_equals_sameValues() {
        AuthController.RegisterReq rr1 = new AuthController.RegisterReq();
        rr1.setEmail("a@b.com");
        rr1.setPassword("pass");
        rr1.setFullName("Name");
        rr1.setRole("DEVELOPER");
        AuthController.RegisterReq rr2 = new AuthController.RegisterReq();
        rr2.setEmail("a@b.com");
        rr2.setPassword("pass");
        rr2.setFullName("Name");
        rr2.setRole("DEVELOPER");
        assertThat(rr1).isEqualTo(rr2);
        assertThat(rr1.hashCode()).isEqualTo(rr2.hashCode());
    }

    @Test
    void registerReq_toString() {
        AuthController.RegisterReq rr = new AuthController.RegisterReq();
        rr.setEmail("test@test.com");
        rr.setPassword("p");
        rr.setFullName("Name");
        String str = rr.toString();
        assertThat(str).contains("test@test.com");
    }
}
