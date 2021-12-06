package onthelive.kr.authServer.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@NoArgsConstructor
@Getter
@Table(name = "tokens")
public class TokenResponseEntity implements Serializable {

    @Id
    @GeneratedValue
    private Long id;

    @Id
    @Column(name="client_id")
    private String clientId;

    @Column(name="access_token" , length = 2000)
    private String accessToken;

    @Column(name="refresh_token")
    private String refreshToken;

    @Column(name="token_type")
    private String tokenType;

    private String scopes;

    private String serializedIdToken;

    public TokenResponseEntity(String clientId, String accessToken, String refreshToken, String tokenType, String scopes, String serializedIdToken) {
        this.clientId = clientId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.scopes = scopes;
        this.serializedIdToken =serializedIdToken;
    }

}
