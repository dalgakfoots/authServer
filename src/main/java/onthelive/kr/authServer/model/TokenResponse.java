package onthelive.kr.authServer.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
/*
* ResponseEntity 로 전달 될 객체임.
* Client Application 에서 Json 으로 받을 때, Key 값이 변수명 과 동일해야 전달 받아짐.
* */
public class TokenResponse {
    private String client_id;
    private String access_token;
    private String refresh_token;
    private String token_type;
    private String scope;
    private String id_token;
}
