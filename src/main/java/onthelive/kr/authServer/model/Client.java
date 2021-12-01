package onthelive.kr.authServer.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Client {

    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String scopes;
}
