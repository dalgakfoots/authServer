package onthelive.kr.authServer.model;

import lombok.Getter;

@Getter
public class OpenIdConfiguration {

    // TODO 데이터 관리 방법에 대해 고려할 것.

    private final String issuer;

    private final String authorization_endpoint;
    private final String token_endpoint;
    private final String introspection_endpoint;
    private final String revocation_endpoint;
    private final String jwks_uri;

    private final String[] response_type_supported;
    private final String[] subject_types_supported;
    private final String[] grant_types_supported;
    private final String[] id_token_signing_alg_values_supported;

    public OpenIdConfiguration() {
        this.issuer = "http://localhost:8091/";
        this.authorization_endpoint = "http://localhost:8091/authorize";
        this.token_endpoint = "http://localhost:8091/token";
        this.introspection_endpoint = "http://localhost:8091/introspect";
        this.revocation_endpoint = "http://localhost:8091/revoke";
        this.jwks_uri = "http://localhost:8091/api/v1/certs";

        this.response_type_supported = new String[]{"code"};
        this.subject_types_supported = new String[]{"public"};
        this.grant_types_supported = new String[]{"authorization_code", "refresh_token"};
        this.id_token_signing_alg_values_supported = new String[]{"RS256"};
    }
}
