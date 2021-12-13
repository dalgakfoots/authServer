package onthelive.kr.authServer.controller;

import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.RsaKeyEntity;
import onthelive.kr.authServer.model.OpenIdConfiguration;
import onthelive.kr.authServer.model.RsaPublicKey;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.persistence.EntityManager;

@RestController
@RequiredArgsConstructor
public class MetaDataController {

    private final EntityManager em;

    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity openIdConfiguration() {
        OpenIdConfiguration openIdConfiguration = new OpenIdConfiguration();
        // TODO Authorization Server 의 메타데이터를 클래스로 관리하고 있음. 관리방법 고려할 것.
        return new ResponseEntity(openIdConfiguration, HttpStatus.OK);
    }

    @GetMapping("/api/v1/certs")
    public ResponseEntity getCerts() {
        RsaKeyEntity rsaKeyEntity = em.find(RsaKeyEntity.class, "onTheLive.kr");
        RsaPublicKey rsaPublicKey = new RsaPublicKey(
                rsaKeyEntity.getAlgorithm(),
                rsaKeyEntity.getPublicExponent(),
                rsaKeyEntity.getModulus(),
                rsaKeyEntity.getKeyType(),
                rsaKeyEntity.getKeyId()
        );

        return new ResponseEntity(rsaPublicKey, HttpStatus.OK);
    }

}
