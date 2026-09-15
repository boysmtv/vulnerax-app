package com.vulnerax.modules.rbac;

import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RbacEntityCoverageTest {

    // ─── Permission ───────────────────────────────────────────

    @Test
    void permission_builder_allFields() {
        Permission p = Permission.builder()
                .name("vuln.read")
                .resource("vulnerability")
                .action("read")
                .description("Read vulnerabilities")
                .build();

        assertThat(p.getName()).isEqualTo("vuln.read");
        assertThat(p.getResource()).isEqualTo("vulnerability");
        assertThat(p.getAction()).isEqualTo("read");
        assertThat(p.getDescription()).isEqualTo("Read vulnerabilities");
    }

    @Test
    void permission_builder_requiredFieldsOnly() {
        Permission p = Permission.builder()
                .name("scan.create")
                .resource("scan")
                .action("create")
                .build();

        assertThat(p.getName()).isEqualTo("scan.create");
        assertThat(p.getResource()).isEqualTo("scan");
        assertThat(p.getAction()).isEqualTo("create");
        assertThat(p.getDescription()).isNull();
    }

    @Test
    void permission_setters() {
        Permission p = new Permission();
        p.setName("role.manage");
        p.setResource("role");
        p.setAction("manage");
        p.setDescription("Manage roles");

        assertThat(p.getName()).isEqualTo("role.manage");
        assertThat(p.getResource()).isEqualTo("role");
        assertThat(p.getAction()).isEqualTo("manage");
        assertThat(p.getDescription()).isEqualTo("Manage roles");
    }

    @Test
    void permission_noArgsConstructor() {
        Permission p = new Permission();
        assertThat(p.getName()).isNull();
        assertThat(p.getResource()).isNull();
        assertThat(p.getAction()).isNull();
        assertThat(p.getDescription()).isNull();
    }

    @Test
    void permission_allArgsConstructor() {
        Permission p = new Permission("user.delete", "user", "delete", "Delete users");
        assertThat(p.getName()).isEqualTo("user.delete");
        assertThat(p.getResource()).isEqualTo("user");
        assertThat(p.getAction()).isEqualTo("delete");
        assertThat(p.getDescription()).isEqualTo("Delete users");
    }

    @Test
    void permission_extendsBaseEntity() {
        UUID id = UUID.randomUUID();
        Permission p = Permission.builder().name("x").resource("x").action("x").build();
        p.setId(id);

        assertThat(p.getId()).isEqualTo(id);
        assertThat(p.getCreatedAt()).isNull();
        assertThat(p.getUpdatedAt()).isNull();
    }

    // ─── RolePermission ───────────────────────────────────────

    @Test
    void rolePermission_builder_allFields() {
        Permission perm = Permission.builder()
                .name("vuln.read")
                .resource("vulnerability")
                .action("read")
                .build();

        RolePermission rp = RolePermission.builder()
                .id(1L)
                .role("ADMIN")
                .permission(perm)
                .build();

        assertThat(rp.getId()).isEqualTo(1L);
        assertThat(rp.getRole()).isEqualTo("ADMIN");
        assertThat(rp.getPermission()).isSameAs(perm);
    }

    @Test
    void rolePermission_builder_withoutId() {
        Permission perm = Permission.builder()
                .name("scan.view")
                .resource("scan")
                .action("view")
                .build();

        RolePermission rp = RolePermission.builder()
                .role("ANALYST")
                .permission(perm)
                .build();

        assertThat(rp.getId()).isNull();
        assertThat(rp.getRole()).isEqualTo("ANALYST");
        assertThat(rp.getPermission()).isSameAs(perm);
    }

    @Test
    void rolePermission_setters() {
        Permission perm = Permission.builder()
                .name("report.export")
                .resource("report")
                .action("export")
                .build();

        RolePermission rp = new RolePermission();
        rp.setId(99L);
        rp.setRole("VIEWER");
        rp.setPermission(perm);

        assertThat(rp.getId()).isEqualTo(99L);
        assertThat(rp.getRole()).isEqualTo("VIEWER");
        assertThat(rp.getPermission()).isSameAs(perm);
    }

    @Test
    void rolePermission_noArgsConstructor() {
        RolePermission rp = new RolePermission();
        assertThat(rp.getId()).isNull();
        assertThat(rp.getRole()).isNull();
        assertThat(rp.getPermission()).isNull();
    }

    @Test
    void rolePermission_allArgsConstructor() {
        Permission perm = Permission.builder()
                .name("api.invoke")
                .resource("api")
                .action("invoke")
                .build();

        RolePermission rp = new RolePermission(5L, "OPERATOR", perm);
        assertThat(rp.getId()).isEqualTo(5L);
        assertThat(rp.getRole()).isEqualTo("OPERATOR");
        assertThat(rp.getPermission()).isSameAs(perm);
    }

    @Test
    void rolePermission_permissionRelationship() {
        Permission perm = Permission.builder()
                .name("config.read")
                .resource("config")
                .action("read")
                .description("Read config")
                .build();

        RolePermission rp = RolePermission.builder()
                .role("ADMIN")
                .permission(perm)
                .build();

        assertThat(rp.getPermission().getName()).isEqualTo("config.read");
        assertThat(rp.getPermission().getResource()).isEqualTo("config");
        assertThat(rp.getPermission().getAction()).isEqualTo("read");
        assertThat(rp.getPermission().getDescription()).isEqualTo("Read config");
    }

    @Test
    void rolePermission_multipleRolesForSamePermission() {
        Permission perm = Permission.builder()
                .name("dashboard.view")
                .resource("dashboard")
                .action("view")
                .build();

        RolePermission rp1 = RolePermission.builder().role("ADMIN").permission(perm).build();
        RolePermission rp2 = RolePermission.builder().role("VIEWER").permission(perm).build();

        assertThat(rp1.getPermission()).isSameAs(rp2.getPermission());
        assertThat(rp1.getRole()).isNotEqualTo(rp2.getRole());
    }

    // ─── RequirePermission annotation ─────────────────────────

    @Test
    void requirePermission_annotationRetention() {
        Class<RequirePermission> rp = RequirePermission.class;
        java.lang.annotation.Retention retention = rp.getAnnotation(Retention.class);
        assertThat(retention).isNotNull();
        assertThat(retention.value()).isEqualTo(RetentionPolicy.RUNTIME);
    }

    @Test
    void requirePermission_annotationTargets() {
        Class<RequirePermission> rp = RequirePermission.class;
        Target target = rp.getAnnotation(Target.class);
        assertThat(target).isNotNull();
        assertThat(target.value()).containsExactlyInAnyOrder(
                ElementType.METHOD, ElementType.TYPE
        );
    }

    @Test
    void requirePermission_annotationDocumented() {
        Class<RequirePermission> rp = RequirePermission.class;
        Documented doc = rp.getAnnotation(Documented.class);
        assertThat(doc).isNotNull();
    }

    @Test
    void requirePermission_annotationValue() throws NoSuchMethodException {
        TestAnnotationHolder holder = new TestAnnotationHolder();
        java.lang.reflect.Method method = holder.getClass().getMethod("annotatedMethod");
        RequirePermission rp = method.getAnnotation(RequirePermission.class);
        assertThat(rp).isNotNull();
        assertThat(rp.value()).isEqualTo("vuln.create");
    }

    @Test
    void requirePermission_annotationNullWhenAbsent() throws NoSuchMethodException {
        TestAnnotationHolder holder = new TestAnnotationHolder();
        java.lang.reflect.Method method = holder.getClass().getMethod("plainMethod");
        RequirePermission rp = method.getAnnotation(RequirePermission.class);
        assertThat(rp).isNull();
    }

    // Helper for annotation reflection tests
    static class TestAnnotationHolder {
        @RequirePermission("vuln.create")
        public void annotatedMethod() {}

        public void plainMethod() {}
    }
}
