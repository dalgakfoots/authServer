package onthelive.kr.authServer.entity;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@NoArgsConstructor
@Getter
@Table(name = "users")
public class UserEntity {
    @Id //@GeneratedValue
    private Long id;

    private String sub;
    private String preferred_username;
    private String name;
    private String email;
    private boolean email_verified;

    public UserEntity(Long id , String sub, String preferred_username, String name, String email, boolean email_verified) {
        this.id = id;
        this.sub = sub;
        this.preferred_username = preferred_username;
        this.name = name;
        this.email = email;
        this.email_verified = email_verified;
    }
}
