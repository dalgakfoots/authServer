package onthelive.kr.authServer.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "clients")
public class ClientEntity implements Serializable {

    public ClientEntity(String clientId , String clientSecret, String redirectUri, String scopes){
        setClientId(clientId);
        setClientSecret(clientSecret);
        setRedirectUri(redirectUri);
        setScopes(scopes);
    }

    @Id @GeneratedValue
    private Long id;

    @Id
    @Column(name = "client_id")
    private String clientId;

    @Id
    @Column(name ="client_secret")
    private String clientSecret;

    @Id
    @Column(name = "redirect_uri")
    private String redirectUri;


    private String scopes;

    private String tokenEndpointAuthMethod;

    private String grantTypes;

    private String responseTypes;

    private Long clientIdCreatedAt;
    private Long clientSecretExpiresAt;

    private String registrationAccessToken;
    private String registrationClientUri;

    @Override
    public String toString() {
        return "ClientEntity{" +
                "id=" + id +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", scopes='" + scopes + '\'' +
                ", tokenEndpointAuthMethod='" + tokenEndpointAuthMethod + '\'' +
                ", grantTypes='" + grantTypes + '\'' +
                ", responseTypes='" + responseTypes + '\'' +
                ", clientIdCreatedAt=" + clientIdCreatedAt +
                ", clientSecretExpiresAt=" + clientSecretExpiresAt +
                ", registrationAccessToken='" + registrationAccessToken + '\'' +
                ", registrationClientUri='" + registrationClientUri + '\'' +
                '}';
    }
}
