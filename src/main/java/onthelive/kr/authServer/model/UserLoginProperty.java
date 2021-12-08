package onthelive.kr.authServer.model;

import lombok.*;

@Data
@AllArgsConstructor
public class UserLoginProperty {
    private String email;
    private boolean isAuthenticated;
}
