package com.vulnerax.modules.identity;

import com.vulnerax.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth/sso")
public class SsoController {

    @GetMapping("/providers")
    public ApiResponse<?> providers() {
        return ApiResponse.ok(new String[]{"PASSWORD","MFA","PASSKEY","SSO-SAML","SSO-OIDC","LDAP","SCIM"});
    }

    @GetMapping("/saml/metadata")
    public ApiResponse<?> samlMetadata() {
        return ApiResponse.ok(Map.of("entityId","https://vulnerax.io/saml", "acsUrl","https://vulnerax.io/api/v1/auth/sso/saml/acs", "cert","MIIBIjANBgkqh..."));
    }

    @GetMapping("/oidc/config")
    public ApiResponse<?> oidc() {
        return ApiResponse.ok(Map.of("issuer","https://vulnerax.io","authorization_endpoint","https://vulnerax.io/oauth2/authorize","token_endpoint","https://vulnerax.io/oauth2/token","scopes","openid profile email"));
    }

    @PostMapping("/scim/users")
    public ApiResponse<?> scimCreate(@RequestBody Map<String,Object> body) {
        return ApiResponse.ok(Map.of("id", java.util.UUID.randomUUID(),"userName", body.get("userName"),"active", true,"provisioned", true));
    }
}
