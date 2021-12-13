package onthelive.kr.authServer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.ClientEntity;
import onthelive.kr.authServer.entity.ProtectedResourceEntity;
import onthelive.kr.authServer.entity.RsaKeyEntity;
import onthelive.kr.authServer.entity.UserEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import javax.persistence.EntityManager;

/*
* 테스트용 데이터 삽입을 위한 클래스임.
*
* */

@Component
@RequiredArgsConstructor
public class InitData {

    private final Preprocess preprocess;

    @PostConstruct
    public void initData(){
        preprocess.prepClient();
        preprocess.prepProtectedResource();
        preprocess.prepUser();
        preprocess.prepRsaKey();
    }

    @Component
    @Transactional
    @RequiredArgsConstructor
    static class Preprocess{

        private final EntityManager em;
        private final RSAKey initRsaKey;

        public void prepClient(){
            ClientEntity client = new ClientEntity("oauth-client-1",
                    "oauth-client-secret-1",
                    "http://localhost:9000/callback",
                    "openid profile email phone address");
            em.persist(client);
        }

        public void prepProtectedResource(){
            ProtectedResourceEntity resource = new ProtectedResourceEntity("protected-resource-1","protected-resource-secret-1");
            em.persist(resource);
        }

        public void prepUser(){
            UserEntity user = new UserEntity(
                    1L,
                    "9XE3-JI34-00132A",
                    "alice",
                    "ALICE",
                    "alice.wonderland@example.com",
                    true);

            em.persist(user);

        }


        public void prepRsaKey(){
            RSAKey publicKey = initRsaKey.toPublicJWK();
            RsaKeyEntity rsaKeyEntity = new RsaKeyEntity(
                    "RS256",
                    publicKey.getPublicExponent().toString(),
                    publicKey.getModulus().toString(),
                    "RSA",
                    publicKey.getKeyID()
            );

            em.persist(rsaKeyEntity);
        }

    }

}
