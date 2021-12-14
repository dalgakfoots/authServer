package onthelive.kr.authServer.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import onthelive.kr.authServer.entity.ClientEntity;
import onthelive.kr.authServer.model.Registration;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;
import javax.persistence.metamodel.EntityType;

@Repository
@RequiredArgsConstructor
@Log4j2
public class ClientRepository {

    private final EntityManager em;

    public ClientEntity getClientEntity(String clientId) {
        try {
            ClientEntity clientEntity = em.createQuery("select c from ClientEntity c " +
                            "where c.clientId = :clientId", ClientEntity.class)
                    .setParameter("clientId", clientId)
                    .getSingleResult();
            return clientEntity;
        } catch (NonUniqueResultException e){
            e.printStackTrace();
            return new ClientEntity();
        } catch (NoResultException e){
            e.printStackTrace();
            return new ClientEntity();
        } catch (Exception e){
            e.printStackTrace();
            return new ClientEntity();
        }
    }

    @Transactional
    public void saveClient(ClientEntity client) {
        em.persist(client);
    }

    @Transactional
    public Registration modifyClient(ClientEntity modifiedClientMetaData, ClientEntity clientEntity) {
        try {


            em.createQuery("update ClientEntity c set c.tokenEndpointAuthMethod = :TEAM , " +
                            "c.grantTypes = :GT , " +
                            "c.responseTypes = : RT , " +
                            "c.redirectUri = : RU , " +
                            "c.scopes = : S " +
                            "where c.clientId = : CI")
                    .setParameter("TEAM", modifiedClientMetaData.getTokenEndpointAuthMethod())
                    .setParameter("GT", modifiedClientMetaData.getGrantTypes())
                    .setParameter("RT", modifiedClientMetaData.getResponseTypes())
                    .setParameter("RU", modifiedClientMetaData.getRedirectUri())
                    .setParameter("S", modifiedClientMetaData.getScopes())
                    .setParameter("CI", clientEntity.getClientId())
                    .executeUpdate();

            clientEntity.setTokenEndpointAuthMethod(modifiedClientMetaData.getTokenEndpointAuthMethod());
            clientEntity.setGrantTypes(modifiedClientMetaData.getGrantTypes());
            clientEntity.setResponseTypes(modifiedClientMetaData.getResponseTypes());
            clientEntity.setRedirectUri(modifiedClientMetaData.getRedirectUri());
            clientEntity.setScopes(modifiedClientMetaData.getScopes());

            Registration returnRegistration = new Registration(
                    clientEntity.getClientId(),
                    clientEntity.getClientSecret(),
                    clientEntity.getRedirectUri(),
                    clientEntity.getScopes(),
                    clientEntity.getTokenEndpointAuthMethod(),
                    clientEntity.getGrantTypes(),
                    clientEntity.getResponseTypes(),
                    clientEntity.getClientIdCreatedAt(),
                    clientEntity.getClientSecretExpiresAt(),
                    clientEntity.getRegistrationAccessToken(),
                    clientEntity.getRegistrationClientUri()
            );

            return returnRegistration;

        } catch (Exception e) {
            e.printStackTrace();
            return new Registration();
        }
    }

    @Transactional
    public void deleteClient(ClientEntity clientEntity) {
        em.remove(clientEntity);
    }
}
