package onthelive.kr.authServer.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import onthelive.kr.authServer.entity.ClientEntity;
import onthelive.kr.authServer.model.Registration;
import onthelive.kr.authServer.repository.ClientRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Service
@RequiredArgsConstructor
@Log4j2
public class ClientService {

    private final ClientRepository clientRepository;

    public void saveClient(ClientEntity client) {
        clientRepository.saveClient(client);
    }

    public ResponseEntity<ClientEntity> checkClientMetadata(Registration request) {
        ClientEntity entity = new ClientEntity();

        if (request.getToken_endpoint_auth_method() != null) {
            entity.setTokenEndpointAuthMethod(request.getToken_endpoint_auth_method());
        } else {
            entity.setTokenEndpointAuthMethod("secret_basic");
        }

        if(!Arrays.stream(new String[]{"secret_basic", "secret_post", "none"})
                .anyMatch(s -> s.equals(entity.getTokenEndpointAuthMethod()))){
            log.error("illegal auth method");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        // TODO 너무 많은 분기처리. 어떻게 줄일 것인가 고려할 것.
        // 에러 상황에 대한 분기처리만 진행 한 뒤, 객체에 생성자로 한번에 데이터 주입하는 것이 괜찮다고 생각.
        if(request.getGrant_types() != null){
            if(request.getResponse_types() != null){
                entity.setGrantTypes(request.getGrant_types());
                entity.setResponseTypes(request.getResponse_types());
                entity.setGrantTypes(request.getGrant_types());
            } else {
                entity.setGrantTypes(request.getGrant_types());
                if (request.getGrant_types().equals("authorization_code")) {
                    entity.setResponseTypes("code");
                }
            }
        } else {

            if(request.getResponse_types() != null){
                entity.setResponseTypes(request.getResponse_types());
                if(request.getGrant_types().equals("code")){
                    entity.setGrantTypes("authorization_code");
                }
            } else {
                entity.setGrantTypes("authorization_code");
                entity.setResponseTypes("code");
            }
        }

        if(!Arrays.stream(new String[]{"authorization_code","refresh_token"}).anyMatch(
                s -> s.equals(entity.getGrantTypes()))
                ||
                !Arrays.stream(new String[]{"code"}).anyMatch(
                        s -> s.equals(entity.getResponseTypes()))
        ){
            log.error("illegal grantTypes or ResponseTypes");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if(request.getRedirect_uris() == null || request.getRedirect_uris().equals("")){
            log.error("illegal redirect uri");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        } else {
            entity.setRedirectUri(request.getRedirect_uris());
        }

        if (request.getScope() != null && !request.getScope().equals("")){
            entity.setScopes(request.getScope());
        }

        return new ResponseEntity<ClientEntity>(entity, HttpStatus.OK);
    }

    public ResponseEntity<ClientEntity> authorizeConfigurationEndpointRequest(HttpServletRequest request , String clientId) {
        String client_id = request.getParameter("client_id");

        if(!request.getMethod().equalsIgnoreCase("get")) {
            if (!client_id.equals(clientId)) {
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        }

        ClientEntity client = clientRepository.getClientEntity(clientId);
        if (client.getClientId() == null){
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }

        String auth = request.getHeader("authorization");
        if(auth != null && auth.toLowerCase().indexOf("bearer") == 0){

            String regToken = auth.substring("bearer ".length());
            if (regToken.equals(client.getRegistrationAccessToken())) {
                return new ResponseEntity<>(client , HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    public Registration modifyClient(ClientEntity modifiedClientMetaData, ClientEntity clientEntity) {
        return clientRepository.modifyClient(modifiedClientMetaData, clientEntity);
    }

    public void deleteClient(ClientEntity clientEntity) {
        clientRepository.deleteClient(clientEntity);
    }
}
