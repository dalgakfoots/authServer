package onthelive.kr.authServer.repository;

import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.*;
import onthelive.kr.authServer.model.Client;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class AuthorRepository {

    private final EntityManager em;


    public RequestEntity getRequest(String reqId) {
        return em.find(RequestEntity.class, reqId);
    }

    public CodeEntity getCode(String key) {
        return em.find(CodeEntity.class, key);
    }

    public TokenResponseEntity getTokenResponse(String clientId) {
        try {

            return em.createQuery("select t from TokenResponseEntity t where t.clientId = :clientId order by t.id desc", TokenResponseEntity.class)
                    .setParameter("clientId", clientId)
                    .setMaxResults(1)
                    .getSingleResult();

        } catch (NoResultException e) {
            e.printStackTrace();
            return new TokenResponseEntity();
        }
    }

    public TokenResponseEntity getTokenResponseByAccessToken(String accessToken) {
        try {

            return em.createQuery("select t from TokenResponseEntity t where t.accessToken = :accessToken", TokenResponseEntity.class)
                    .setParameter("accessToken", accessToken)
                    .getSingleResult();

        } catch (NoResultException e) {
            e.printStackTrace();
            return new TokenResponseEntity();
        }
    }

    public Client getClient(String clientId) {
        try {
            ClientEntity findResult = em.createQuery("select c from ClientEntity c where c.clientId = :clientId", ClientEntity.class)
                    .setParameter("clientId", clientId)
                    .getSingleResult();

            return new Client(findResult.getClientId(), findResult.getClientSecret(), findResult.getRedirectUri(), findResult.getScopes());

        } catch (NoResultException e) {
            e.printStackTrace();
            return new Client("", "", "", "");
        }
    }


    public ProtectedResourceEntity getProtectedResource(String id) {
        ProtectedResourceEntity protectedResource = null;
        try {
            protectedResource = em.createQuery("select p from ProtectedResourceEntity p where p.resourceId = :resourceId", ProtectedResourceEntity.class)
                    .setParameter("resourceId", id)
                    .getSingleResult();
            return protectedResource;
        }catch (NoResultException e){
            protectedResource = new ProtectedResourceEntity();
            return protectedResource;
        }
    }

    public UserEntity getUser(String user) {
        try {
            UserEntity userEntity = em.createQuery("select u from UserEntity u where u.preferred_username = :userName", UserEntity.class)
                    .setParameter("userName", user)
                    .getSingleResult();
            return userEntity;
        }catch (NoResultException e){
            e.printStackTrace();
            return new UserEntity();
        }catch (NonUniqueResultException e){
            e.printStackTrace();
            return new UserEntity();
        }
    }
    @Transactional
    public void saveRequest(RequestEntity requestEntity) {
        em.persist(requestEntity);
    }

    @Transactional
    public void removeRequest(String reqId) {
        em.remove(em.find(RequestEntity.class, reqId));
    }

    @Transactional
    public void saveCode(CodeEntity codeEntity) {
        em.persist(codeEntity);
    }

    @Transactional
    public void removeCode(String key) {
        em.remove(em.find(CodeEntity.class, key));
    }

    @Transactional
    public TokenResponseEntity saveTokenResponse(TokenResponseEntity tokenResponse) {
        em.persist(tokenResponse);
        return tokenResponse;
    }

    @Transactional
    public void removeTokenResponseByRefreshToken(String refreshToken) {
        em.createQuery("delete from TokenResponseEntity t where t.refreshToken = :refreshToken")
                .setParameter("refreshToken", refreshToken)
                .executeUpdate();
    }

    @Transactional
    public void removeTokenResponse(TokenResponseEntity tokenResponseEntity) {
        em.createQuery("delete from TokenResponseEntity t where t.clientId = :clientId")
                .setParameter("clientId", tokenResponseEntity.getClientId())
                .executeUpdate();
    }


}
