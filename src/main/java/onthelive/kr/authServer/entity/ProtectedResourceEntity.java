package onthelive.kr.authServer.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "resources")
public class ProtectedResourceEntity {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(name = "resource_secret")
    private String resourceSecret;

    public ProtectedResourceEntity(String resourceId, String resourceSecret) {
        this.resourceId = resourceId;
        this.resourceSecret = resourceSecret;
    }
}
