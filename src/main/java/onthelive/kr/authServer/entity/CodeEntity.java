package onthelive.kr.authServer.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Table(name = "codes")
public class CodeEntity {

    @Id
    @Column(name="code_id")
    private String codeId;

    @Column(name = "request_id")
    private String requestId;

    @Column(name ="response_type")
    private String responseType;

    @Column(name="redirect_uri")
    private String redirectUri;

    private String state;

    @Column(name="client_id")
    private String clientId;

    private String scopes;

    private String user;

}
