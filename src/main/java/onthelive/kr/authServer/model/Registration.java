package onthelive.kr.authServer.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Registration {
    // client 등록 시, client 로 들어오고 나가는 DTO
    // TODO 변수명 명명 방식 고려할 것.

    private String client_id;
    private String client_secret;
    private String redirect_uris;
    private String scope;
    private String token_endpoint_auth_method;
    private String grant_types;
    private String response_types;

    private Long client_id_created_at;
    private Long client_secret_expires_at;

    private String registration_access_token;
    private String registration_client_uri;

    @Override
    public String toString() {
        return "Registration{" +
                "client_id='" + client_id + '\'' +
                ", client_secret='" + client_secret + '\'' +
                ", redirect_uris='" + redirect_uris + '\'' +
                ", scope='" + scope + '\'' +
                ", token_endpoint_auth_method='" + token_endpoint_auth_method + '\'' +
                ", grant_types='" + grant_types + '\'' +
                ", response_types='" + response_types + '\'' +
                ", client_id_created_at=" + client_id_created_at +
                ", client_secret_expires_at=" + client_secret_expires_at +
                ", registration_access_token='" + registration_access_token + '\'' +
                ", registration_client_uri='" + registration_client_uri + '\'' +
                '}';
    }
}
