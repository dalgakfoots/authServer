package onthelive.kr.authServer.entity;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@NoArgsConstructor
@Getter
@Table(name = "requests")
public class RequestEntity{

    public RequestEntity(String requestId, String responseType, String redirectUri, String state, String clientId) {
        this.requestId = requestId;
        this.responseType = responseType;
        this.redirectUri = redirectUri;
        this.state = state;
        this.clientId = clientId;
    }

    @Id
    @Column(name = "request_id")
    private String requestId;

    @Column(name ="response_type")
    private String responseType;

    @Column(name="redirect_uri")
    private String redirectUri;

    private String state;

    @Column(name="client_id")
    private String clientId;
}
