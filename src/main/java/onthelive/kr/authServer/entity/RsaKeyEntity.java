package onthelive.kr.authServer.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.ColumnDefault;

import javax.persistence.*;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "RSAKEY")
public class RsaKeyEntity {

    @ColumnDefault("'RS256'")
    private String algorithm;

    private String publicExponent;

    @Column(length = 2048)
    private String modulus;

    @ColumnDefault("'RSA'")
    private String keyType;

    @Id
    private String keyId;

}
