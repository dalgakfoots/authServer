package onthelive.kr.authServer.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RsaPublicKey {

    private String alg; // algorithm
    private String e; // publicExponent
    private String n; //modulus
    private String kty; // keyType
    private String kid; // keyId

}
