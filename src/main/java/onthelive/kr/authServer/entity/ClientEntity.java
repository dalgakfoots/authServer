package onthelive.kr.authServer.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter(AccessLevel.PRIVATE)
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

}
